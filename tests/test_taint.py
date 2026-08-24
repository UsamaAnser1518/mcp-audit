"""The taint engine, tested directly.

MCP003 and MCP004 both sit on this, so a bug here is a bug in two rules at
once and the rule-level tests would only show it obliquely.
"""

import ast

from mcp_audit.astutil import build_alias_map
from mcp_audit.taint import (
    analyse,
    is_dynamic_string,
    is_tainted,
    looks_guarded,
    taint_origins,
)

IMPORT_SHLEX = "import shlex\n"
FROM_IMPORT_QUOTE = "from shlex import quote\n"
RETURN_QUOTE = "    return shlex.quote(value)\n"
RETURN_BARE_QUOTE = "    return quote(value)\n"


def _analyse(body: str, params=("value",), preamble: str = ""):
    """The function node, its TaintSet, and an origins() bound to its aliases."""
    source = preamble + f"def tool({', '.join(params)}):\n" + body
    tree = ast.parse(source)
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
    aliases = build_alias_map(tree)
    taints = analyse(func, params, aliases)

    def origins(node):
        return taint_origins(node, taints, aliases)

    return func, taints, origins


def _last_expression(func):
    return func.body[-1].value


def test_parameter_is_tainted():
    func, taints, origins = _analyse("    return value\n")
    assert origins(_last_expression(func)) == {"value"}


def test_unrelated_name_is_not_tainted():
    func, taints, origins = _analyse("    other = 1\n    return other\n")
    assert origins(_last_expression(func)) == set()


def test_taint_flows_through_an_alias():
    func, taints, origins = _analyse("    local = value\n    return local\n")
    assert origins(_last_expression(func)) == {"value"}


def test_taint_flows_backwards_through_source_order():
    """Flow-insensitive: the union over the body, not a per-statement state."""
    func, taints, origins = _analyse("    if 1:\n        b = a\n    a = value\n    return b\n")
    assert origins(_last_expression(func)) == {"value"}


def test_augmented_assignment_taints_the_target():
    func, taints, origins = _analyse(
        "    command = 'ls '\n    command += value\n    return command\n"
    )
    assert origins(_last_expression(func)) == {"value"}


def test_for_loop_target_is_tainted():
    func, taints, origins = _analyse("    for item in value:\n        pass\n    return item\n")
    assert origins(_last_expression(func)) == {"value"}


def test_with_binding_is_tainted():
    func, taints, origins = _analyse("    with value as handle:\n        pass\n    return handle\n")
    assert origins(_last_expression(func)) == {"value"}


def test_walrus_is_tainted():
    func, taints, origins = _analyse("    return (local := value)\n")
    assert is_tainted(_last_expression(func), taints)


def test_tuple_unpacking_taints_every_slot():
    func, taints, origins = _analyse("    left, right = value\n    return right\n")
    assert origins(_last_expression(func)) == {"value"}


def test_attribute_write_taints_that_path_only():
    func, taints, origins = _analyse("    holder.command = value\n    return holder.other\n")
    assert "holder.command" in taints
    assert origins(_last_expression(func)) == set()


def test_subscript_write_taints_the_container():
    func, taints, origins = _analyse("    store['k'] = value\n    return store['k']\n")
    assert origins(_last_expression(func)) == {"value"}


def test_container_literal_carries_taint():
    func, taints, origins = _analyse("    return ['ls', value]\n")
    assert origins(_last_expression(func)) == {"value"}


def test_multiple_parameters_report_every_origin():
    func, taints, origins = _analyse("    return f'{a} {b}'\n", params=("a", "b"))
    assert origins(_last_expression(func)) == {"a", "b"}


def test_int_coercion_clears_taint():
    func, taints, origins = _analyse("    return int(value)\n")
    assert origins(_last_expression(func)) == set()


def test_shlex_quote_clears_taint():
    func, _, origins = _analyse(RETURN_QUOTE, preamble=IMPORT_SHLEX)
    assert origins(_last_expression(func)) == set()


def test_shlex_quote_via_from_import_still_clears_taint():
    """The alias map is what makes the from-import shape resolve."""
    func, _, origins = _analyse(RETURN_BARE_QUOTE, preamble=FROM_IMPORT_QUOTE)
    assert origins(_last_expression(func)) == set()


def test_str_does_not_clear_taint():
    func, taints, origins = _analyse("    return str(value)\n")
    assert origins(_last_expression(func)) == {"value"}


def test_interpolation_is_recorded_for_the_sql_check():
    func, taints, origins = _analyse("    query = f'select {value}'\n    return query\n")
    assert taints.is_interpolated("query")
    assert is_dynamic_string(_last_expression(func), taints)


def test_plain_alias_is_not_marked_interpolated():
    func, taints, origins = _analyse("    query = value\n    return query\n")
    assert not taints.is_interpolated("query")
    assert not is_dynamic_string(_last_expression(func), taints)


def test_percent_and_format_count_as_interpolation():
    func, taints, origins = _analyse("    query = 'select %s' % value\n    return query\n")
    assert taints.is_interpolated("query")
    func, taints, origins = _analyse("    query = 'select {}'.format(value)\n    return query\n")
    assert taints.is_interpolated("query")


def test_no_parameters_means_no_work():
    func, taints, origins = _analyse("    return 1\n", params=())
    assert not taints
    assert origins(_last_expression(func)) == set()


def test_guard_recognises_a_branch_that_raises():
    func, taints, _ = _analyse(
        "    if not value:\n        raise ValueError(value)\n    return value\n"
    )
    assert looks_guarded(func, taints)


def test_guard_recognises_a_named_validator():
    func, taints, _ = _analyse("    validate_path(value)\n    return value\n")
    assert looks_guarded(func, taints)


def test_guard_recognises_a_method_on_the_value():
    func, taints, _ = _analyse("    value.relative_to(BASE)\n    return value\n")
    assert looks_guarded(func, taints)


def test_guard_ignores_a_branch_that_falls_through():
    func, taints, _ = _analyse("    if value:\n        pass\n    return value\n")
    assert not looks_guarded(func, taints)


def test_guard_ignores_a_check_of_something_else():
    func, taints, _ = _analyse("    validate_path(other)\n    return value\n")
    assert not looks_guarded(func, taints)


def test_subprocess_check_calls_are_not_guards():
    func, taints, _ = _analyse(
        "    subprocess.check_output(value)\n    return value\n", preamble="import subprocess\n"
    )
    assert not looks_guarded(func, taints, build_alias_map(ast.parse("import subprocess")))
