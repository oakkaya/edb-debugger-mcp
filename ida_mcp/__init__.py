"""IDA Pro EDB Debugger Bridge — plugin entry point.

This is the IDA Pro EDB Debugger Bridge plugin. When loaded by IDA,
it registers debugger-control actions under the Edit → EDB Debugger menu.
"""

from . import ida_bridge


def PLUGIN_ENTRY():
    ida_bridge.register_actions()
