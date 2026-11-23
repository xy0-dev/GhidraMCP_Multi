import asyncio
import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from ghidra_mcp.backend import GhidraBackend
from ghidra_mcp.server import GUI_ONLY_TOOLS, create_server


def tool_names(mcp) -> set[str]:
    return {t.name for t in asyncio.run(mcp.list_tools())}


def call(mcp, tool, **args):
    result = asyncio.run(mcp.call_tool(tool, args))
    if isinstance(result, tuple):
        return result[1]
    return json.loads(result[0].text)


@pytest.mark.parametrize("capabilities", [None, {"gui_context"}])
def test_gui_tools_registered_when_available_or_unknown(capabilities):
    names = tool_names(create_server(GhidraBackend(), capabilities=capabilities))
    assert set(GUI_ONLY_TOOLS) <= names


def test_gui_tools_hidden_in_headless():
    names = tool_names(create_server(GhidraBackend(), capabilities=set()))
    assert not set(GUI_ONLY_TOOLS) & names
    assert {"get_program_info", "read_memory", "get_function_calls", "list_functions"} <= names


def test_backend_error_becomes_tool_error(fake_backend):
    fake_backend.fail("/decompile", 409, "AMBIGUOUS_NAME", "'f' matches 2 functions")
    mcp = create_server(GhidraBackend(fake_backend.url))
    with pytest.raises(ToolError, match="AMBIGUOUS_NAME"):
        asyncio.run(mcp.call_tool("decompile_function", {"name": "f"}))


def test_structured_result_is_passed_through(fake_backend):
    page = {"items": [{"name": "main", "address": "00401000"}], "offset": 0, "limit": 100,
            "total": 1, "has_more": False}
    fake_backend.ok("/functions", page)
    mcp = create_server(GhidraBackend(fake_backend.url))
    assert call(mcp, "list_functions", filter="ma") == page
    assert fake_backend.requests[-1][2]["filter"] == "ma"


def test_list_methods_is_alias_returning_names(fake_backend):
    fake_backend.ok("/functions", {"items": [{"name": "a", "address": "1"}, {"name": "b", "address": "2"}],
                                   "offset": 0, "limit": 100, "total": 2, "has_more": False})
    mcp = create_server(GhidraBackend(fake_backend.url))
    assert call(mcp, "list_methods") == {"result": ["a", "b"]}


def test_rename_variable_requires_function_identity():
    mcp = create_server(GhidraBackend("http://127.0.0.1:1/"))
    with pytest.raises(ToolError, match="MISSING_PARAMETER"):
        asyncio.run(mcp.call_tool("rename_variable", {"old_name": "a", "new_name": "b"}))


def test_list_and_switch_program(fake_backend):
    programs = {"programs": [{"id": "/a.exe", "name": "a.exe", "active": True},
                             {"id": "/b.dll", "name": "b.dll", "active": False}],
                "active": "/a.exe"}
    fake_backend.ok("/programs", programs)
    fake_backend.ok("/switch_program", {"active": "/b.dll", "name": "b.dll"})
    mcp = create_server(GhidraBackend(fake_backend.url))
    assert call(mcp, "list_programs") == programs
    assert call(mcp, "switch_program", program="b.dll")["active"] == "/b.dll"
    assert fake_backend.requests[-1][:2] == ("POST", "/switch_program")
    assert fake_backend.requests[-1][2]["program"] == "b.dll"


def test_program_argument_is_forwarded_only_when_given(fake_backend):
    fake_backend.ok("/functions", {"items": [], "offset": 0, "limit": 100, "total": 0, "has_more": False})
    mcp = create_server(GhidraBackend(fake_backend.url))
    call(mcp, "list_functions")
    assert "program" not in fake_backend.requests[-1][2]
    call(mcp, "list_functions", program="/b.dll")
    assert fake_backend.requests[-1][2]["program"] == "/b.dll"


def test_every_program_tool_accepts_program_argument():
    mcp = create_server(GhidraBackend())
    for tool in asyncio.run(mcp.list_tools()):
        if tool.name == "list_programs":
            continue
        assert "program" in tool.inputSchema["properties"], tool.name
