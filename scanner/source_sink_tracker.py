"""
source_sink_tracker.py
----------------------
Tracks variable data flow: source -> transforms -> sink.
Handles alias chains (a = b = c = data) and multi-hop transforms.
"""

import ast


NETWORK_SINKS = {
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.request",

    "socket.send",
    "socket.sendall",

    "ftplib.FTP.storbinary",

    "smtplib.SMTP.sendmail",

    "urllib.request.urlopen",

    "websocket.send",

    "paramiko.SSHClient.exec_command",
}


TRANSFORM_FUNCTIONS = {
    "base64.b64encode": "base64_encode",
    "base64.encodebytes": "base64_encode",

    "zlib.compress": "zlib_compress",
    "gzip.compress": "gzip_compress",

    "binascii.hexlify": "hexlify",

    "json.dumps": "json_serialize",

    "pickle.dumps": "serialize",

    "str.encode": "encode",
}


def get_call_name(node):
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)

        if parent:
            return f"{parent}.{node.attr}"

        return node.attr

    return None


def detect_source(call_name):

    if call_name == "open":
        return "file_read"

    if call_name == "os.getenv":
        return "env_var"

    if call_name == "os.environ.get":
        return "env_var"

    if call_name == "getpass.getpass":
        return "credential"

    if call_name == "input":
        return "user_input"

    if call_name == "requests.get":
        return "network_recv"

    if call_name == "socket.recv":
        return "network_recv"

    return None


class SourceSinkTracker:

    def __init__(self):

        self.variable_sources = {}
        self.variable_transforms = {}
        self.variable_aliases = {}

        self.variable_versions = {}

        self.file_handles = {}
        self.flows = []


    def create_new_version(self, var):

        version = (
            self.variable_versions.get(var, 0)
            + 1
        )

        self.variable_versions[var] = version

        return f"{var}#{version}"
    


    def current_version(self, var):

        version = self.variable_versions.get(var)

        if version is None:
            return var

        return f"{var}#{version}"
    # =====================================
    # PASS 1 - TRACK VARIABLES
    # =====================================

    def track(self, tree):

        for node in tree.body:

            if isinstance(node, ast.With):
                self._handle_with(node)

                for stmt in node.body:

                    if isinstance(stmt, ast.Assign):
                        self._handle_assignment(stmt)

            elif isinstance(node, ast.Assign):
                self._handle_assignment(node)
    # =====================================
    # WITH OPEN(...)
    # =====================================

    def _handle_with(self, node):

        for item in node.items:

            if not isinstance(
                item.context_expr,
                ast.Call
            ):
                continue

            if (
                get_call_name(
                    item.context_expr.func
                )
                != "open"
            ):
                continue

            if (
                item.optional_vars
                and isinstance(
                    item.optional_vars,
                    ast.Name
                )
            ):

                self.file_handles[
                    item.optional_vars.id
                ] = "file_read"

    # =====================================
    # ASSIGNMENTS
    # =====================================

    def _handle_assignment(self, node):

        if not node.targets:
            return

        target = node.targets[0]

        if not isinstance(
            target,
            ast.Name
        ):
            return

        var = target.id

        # --------------------------
        # Alias propagation
        # x = y
        # --------------------------

        if isinstance(
            node.value,
            ast.Name
        ):

            left = self.create_new_version(var)

            right = self.current_version(
                node.value.id
            )

            self.variable_aliases[left] = right

        # --------------------------
        # Function calls
        # --------------------------

        if isinstance(
            node.value,
            ast.Call
        ):

            func = node.value.func

            cname = get_call_name(func)
            # Normalize variable.encode() calls

            if (
                isinstance(func, ast.Attribute)
                and func.attr == "encode"
            ):
                cname = "str.encode"

            # --------------------------
            # f.read()
            # --------------------------

            if (
                isinstance(
                    func,
                    ast.Attribute
                )
                and func.attr == "read"
                and isinstance(
                    func.value,
                    ast.Name
                )
                and func.value.id
                in self.file_handles
            ):

                versioned_var = self.create_new_version(var)
                self.variable_sources[
                    versioned_var
                ] = "file_read"

            # --------------------------
            # Direct Sources
            # --------------------------

            src = detect_source(cname)

            if src:

                versioned_var = self.create_new_version(var)
                self.variable_sources[
                    versioned_var
                ] = src

            # --------------------------
            # Transforms
            # --------------------------

            if cname in TRANSFORM_FUNCTIONS:

                # ----------------------------------
                # str.encode()
                # ----------------------------------

                if cname == "str.encode":

                    if (
                        isinstance(func, ast.Attribute)
                        and isinstance(func.value, ast.Name)
                    ):

                        input_var = self.current_version(
                            func.value.id
                        )

                        new_var = self.create_new_version(var)

                        if func.value.id == var:

                            previous_version = (
                                self.variable_versions[var] - 1
                            )

                            if previous_version > 0:

                                input_var = (
                                    f"{var}#{previous_version}"
                                )

                        self.variable_transforms[new_var] = {

                            "transform": "encode",

                            "input": input_var
                        }

                    return


                # ----------------------------------
                # Normal transforms
                # ----------------------------------

                if not node.value.args:
                    return

                arg = node.value.args[0]
                # --------------------------
                # Case 1:
                # base64.b64encode(data)
                # --------------------------

                if isinstance(arg, ast.Name):

                    # Capture previous version BEFORE
                    # creating the new version

                    input_var = self.current_version(
                        arg.id
                    )

                    new_var = self.create_new_version(var)

                    # Self-reassignment case:
                    # data = base64.b64encode(data)

                    if arg.id == var:

                        previous_version = (
                            self.variable_versions[var] - 1
                        )

                        if previous_version > 0:

                            input_var = (
                                f"{var}#{previous_version}"
                            )

                    self.variable_transforms[new_var] = {

                        "transform":
                            TRANSFORM_FUNCTIONS[cname],

                        "input":
                            input_var
                    }


                # --------------------------
                # Case 2:
                # base64.b64encode(
                #     token.encode()
                # )
                # --------------------------

                elif isinstance(arg, ast.Call):

                    if (
                        isinstance(arg.func, ast.Attribute)
                        and arg.func.attr == "encode"
                        and isinstance(arg.func.value, ast.Name)
                    ):

                        original_var = arg.func.value.id

                        temp_var = f"{var}_inner"

                        self.variable_transforms[temp_var] = {

                            "transform": "encode",

                            "input": self.current_version(
                                original_var
                            ),
                        }

                        new_var = self.create_new_version(var)

                        self.variable_transforms[new_var] = {

                            "transform":
                                TRANSFORM_FUNCTIONS[cname],

                            "input":
                                temp_var,
                        }

    # =====================================
    # ALIAS RESOLUTION
    # =====================================

    def _resolve_alias(self, var):

        visited = set()

        while (
            var
            in self.variable_aliases
            and var
            not in visited
        ):

            visited.add(var)

            var = (
                self.variable_aliases[
                    var
                ]
            )

        return var

    # =====================================
    # TRANSFORM CHAIN
    # =====================================

    def _resolve_transform_chain(
        self,
        var
    ):

        transforms = []

        visited = set()

        current = var

        while (
            current
            in self.variable_transforms
            and current
            not in visited
        ):

            visited.add(current)

            info = (
                self.variable_transforms[
                    current
                ]
            )

            transforms.append(
                info["transform"]
            )

            current = self._resolve_alias(
                info["input"]
            )

        return (
            current,
            list(
                reversed(
                    transforms
                )
            )
        )

    # =====================================
    # PASS 2 - SINKS
    # =====================================

    def detect_sinks(self, tree):

        for node in ast.walk(tree):

            if not isinstance(
                node,
                ast.Call
            ):
                continue

            cname = get_call_name(
                node.func
            )

            if (
                cname
                not in NETWORK_SINKS
            ):
                continue

            args = (
                list(node.args)
                +
                [
                    kw.value
                    for kw
                    in node.keywords
                ]
            )

            for arg in args:

                # variable

                if isinstance(
                    arg,
                    ast.Name
                ):

                    latest = self.current_version(
                        arg.id
                    )

                    self._resolve_flow(
                        latest,
                        cname
                    )

                # dict literal

                elif isinstance(
                    arg,
                    ast.Dict
                ):

                    for value in arg.values:

                        if isinstance(
                            value,
                            ast.Name
                        ):

                            latest = self.current_version(
                                value.id
                            )

                            self._resolve_flow(
                                latest,
                                cname
                            )

    # =====================================
    # FLOW RESOLUTION
    # =====================================

    def _resolve_flow(
        self,
        var,
        sink
    ):

        resolved = self._resolve_alias(
            var
        )

        # --------------------------
        # Source -> Sink
        # --------------------------

        if (
            resolved
            in self.variable_sources
        ):

            self.flows.append({

                "source":
                    self.variable_sources[
                        resolved
                    ],

                "transforms":
                    [],

                "sink":
                    sink,

                "source_var":
                    resolved,

                "sink_call":
                    sink,
            })

            return

        # --------------------------
        # Source -> Transforms -> Sink
        # --------------------------

        source_var, transforms = (
            self._resolve_transform_chain(
                resolved
            )
        )

        if (
            source_var
            in self.variable_sources
        ):

            self.flows.append({

                "source":
                    self.variable_sources[
                        source_var
                    ],

                "transforms":
                    transforms,

                "sink":
                    sink,

                "source_var":
                    source_var,

                "sink_call":
                    sink,
            })

    # =====================================
    # RESULTS
    # =====================================

    def get_flows(self):

        return self.flows


# ==========================================
# PUBLIC API
# ==========================================

def analyze_data_flow(tree):

    tracker = SourceSinkTracker()

    tracker.track(tree)

    tracker.detect_sinks(tree)

    return tracker.get_flows()