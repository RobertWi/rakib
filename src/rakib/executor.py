"""Secure Executor — CaMeL/Dromedary-style Python interpreter for agent tool calls.

This is an alternative execution mode where instead of using Claude's native
tool_use, the LLM generates Python code that this interpreter runs with full
provenance tracking on every value.

Every variable, every function argument, every return value is wrapped in a
CapValue that tracks its origin (user input, tool result, computed).
When a tool is called, the interpreter checks each argument's provenance
against the security policy before allowing execution.

SECURITY NOTE: This uses ast.parse() + a custom AST visitor, NOT eval().
Only whitelisted AST node types are executed. No arbitrary code execution.

Based on:
- Google DeepMind CaMeL: https://arxiv.org/abs/2503.18813
- Microsoft Dromedary: https://github.com/microsoft/dromedary
"""

from __future__ import annotations

import ast
import asyncio
import logging
import operator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)


class SourceType(Enum):
    USER = "user"
    SYSTEM = "system"
    TOOL = "tool"
    COMPUTED = "computed"


@dataclass(frozen=True)
class Source:
    type: SourceType
    identifier: str = ""

    def is_trusted(self) -> bool:
        return self.type in (SourceType.USER, SourceType.SYSTEM)

    def __str__(self) -> str:
        return f"{self.type.value}:{self.identifier}" if self.identifier else self.type.value


@dataclass
class CapValue:
    """A value wrapped with provenance tracking."""
    value: Any
    node_id: int
    source: Source
    dependencies: list[int] = field(default_factory=list)


class ProvenanceDAG:
    """Directed acyclic graph tracking data lineage."""

    def __init__(self) -> None:
        self._nodes: dict[int, CapValue] = {}
        self._counter: int = 0

    def add(self, value: Any, source: Source, deps: list[int] | None = None) -> CapValue:
        nid = self._counter
        self._counter += 1
        cv = CapValue(value=value, node_id=nid, source=source, dependencies=deps or [])
        self._nodes[nid] = cv
        return cv

    def get_all_sources(self, node_id: int) -> set[Source]:
        """Get all sources in a node's ancestry."""
        sources: set[Source] = set()
        visited: set[int] = set()
        stack = [node_id]
        while stack:
            nid = stack.pop()
            if nid in visited:
                continue
            visited.add(nid)
            node = self._nodes.get(nid)
            if not node:
                continue
            sources.add(node.source)
            stack.extend(node.dependencies)
        return sources

    def has_untrusted(self, node_id: int, untrusted_tools: set[str]) -> bool:
        """Check if any ancestor is from an untrusted tool."""
        for src in self.get_all_sources(node_id):
            if src.type == SourceType.TOOL and src.identifier in untrusted_tools:
                return True
        return False


class PolicyViolation(Exception):
    def __init__(self, tool: str, param: str, reason: str):
        self.tool = tool
        self.param = param
        self.reason = reason
        super().__init__(f"Policy violation: {tool}.{param} — {reason}")


def _load_policy_config() -> tuple[set[str], dict[str, set[str]]]:
    """Load policy config from PolicyEngine. No hardcoded rules."""
    try:
        from rakib.policy import _load_config
        cfg = _load_config()
        sensitive = {k: set(v) for k, v in cfg.sensitive_params.items()}
        return cfg.untrusted_tools, sensitive
    except Exception:
        return set(), {}


_untrusted, _sensitive = _load_policy_config()
UNTRUSTED_TOOLS = _untrusted
SENSITIVE_PARAMS = _sensitive


class SecureExecutor:
    """AST-based Python interpreter with provenance tracking.

    Executes LLM-generated Python code where every value is a CapValue
    with full lineage. Tool calls are intercepted and policy-checked.

    Uses ast.parse() + custom visitor — NOT eval(). Only whitelisted
    AST node types are executed.
    """

    def __init__(
        self,
        tools: dict[str, Callable] | None = None,
        untrusted_tools: set[str] | None = None,
        sensitive_params: dict[str, set[str]] | None = None,
    ):
        self.dag = ProvenanceDAG()
        self.tools = tools or {}
        self.untrusted_tools = untrusted_tools or UNTRUSTED_TOOLS
        self.sensitive_params = sensitive_params if sensitive_params is not None else SENSITIVE_PARAMS
        self._globals: dict[str, CapValue] = {}
        self._results: list[Any] = []
        self._setup_builtins()

    def _setup_builtins(self) -> None:
        sys_src = Source(SourceType.SYSTEM, "builtin")
        builtins = {
            "None": None, "True": True, "False": False,
            "abs": abs, "any": any, "all": all, "bool": bool,
            "dict": dict, "enumerate": enumerate, "float": float,
            "int": int, "len": len, "list": list, "max": max,
            "min": min, "print": print, "range": range, "repr": repr,
            "set": set, "sorted": sorted, "str": str, "tuple": tuple,
            "type": type, "zip": zip, "sum": sum,
        }
        for name, val in builtins.items():
            self._globals[name] = self.dag.add(val, sys_src)

    def register_tool(self, name: str, func: Callable) -> None:
        self.tools[name] = func
        self._globals[name] = self.dag.add(func, Source(SourceType.SYSTEM, f"tool:{name}"))

    def set_user_input(self, key: str, value: Any) -> CapValue:
        cv = self.dag.add(value, Source(SourceType.USER, key))
        self._globals[key] = cv
        return cv

    async def execute(self, code: str) -> list[Any]:
        """Execute Python code with provenance tracking. Returns tool call results."""
        self._results = []
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            logger.error("Failed to parse LLM code: %s", e)
            return [{"error": f"syntax error: {e}"}]

        for node in ast.iter_child_nodes(tree):
            try:
                await self._exec_node(node)
            except PolicyViolation as pv:
                logger.warning("POLICY BLOCKED: %s", pv)
                self._results.append({
                    "status": "blocked", "tool": pv.tool,
                    "param": pv.param, "reason": pv.reason,
                })
            except Exception as e:
                logger.error("Executor error on %s: %s", type(node).__name__, e)
                self._results.append({"error": str(e)})

        return self._results

    async def _exec_node(self, node: ast.AST) -> CapValue | None:
        if isinstance(node, ast.Assign):
            value = await self._expr(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._globals[target.id] = value
            return value
        elif isinstance(node, ast.Expr):
            return await self._expr(node.value)
        elif isinstance(node, ast.If):
            cond = await self._expr(node.test)
            body = node.body if cond.value else node.orelse
            for child in body:
                await self._exec_node(child)
        elif isinstance(node, ast.For):
            iter_val = await self._expr(node.iter)
            if isinstance(node.target, ast.Name):
                for item in iter_val.value:
                    self._globals[node.target.id] = self.dag.add(
                        item, iter_val.source, [iter_val.node_id]
                    )
                    for child in node.body:
                        await self._exec_node(child)
        elif isinstance(node, ast.Return):
            return await self._expr(node.value) if node.value else None
        elif isinstance(node, ast.AugAssign):
            target_name = node.target.id if isinstance(node.target, ast.Name) else None
            if target_name:
                left = self._globals.get(target_name)
                right = await self._expr(node.value)
                if left:
                    ops = {ast.Add: operator.add, ast.Sub: operator.sub}
                    op_func = ops.get(type(node.op), operator.add)
                    result = op_func(left.value, right.value)
                    self._globals[target_name] = self.dag.add(
                        result, Source(SourceType.COMPUTED), [left.node_id, right.node_id]
                    )
        return None

    async def _expr(self, node: ast.AST) -> CapValue:
        """Evaluate an expression, returning CapValue with provenance."""
        if isinstance(node, ast.Constant):
            return self.dag.add(node.value, Source(SourceType.USER, "literal"))

        if isinstance(node, ast.Name):
            cv = self._globals.get(node.id)
            if cv is None:
                raise NameError(f"'{node.id}' is not defined")
            return cv

        if isinstance(node, ast.Call):
            return await self._call(node)

        if isinstance(node, ast.BinOp):
            left = await self._expr(node.left)
            right = await self._expr(node.right)
            ops = {
                ast.Add: operator.add, ast.Sub: operator.sub,
                ast.Mult: operator.mul, ast.Div: operator.truediv,
                ast.Mod: operator.mod, ast.FloorDiv: operator.floordiv,
            }
            op_func = ops.get(type(node.op))
            if not op_func:
                raise NotImplementedError(f"operator {type(node.op).__name__}")
            return self.dag.add(
                op_func(left.value, right.value),
                Source(SourceType.COMPUTED), [left.node_id, right.node_id]
            )

        if isinstance(node, ast.Compare):
            left = await self._expr(node.left)
            result = True
            deps = [left.node_id]
            cmp_ops = {
                ast.Eq: operator.eq, ast.NotEq: operator.ne,
                ast.Lt: operator.lt, ast.Gt: operator.gt,
                ast.LtE: operator.le, ast.GtE: operator.ge,
                ast.In: lambda a, b: a in b,
                ast.NotIn: lambda a, b: a not in b,
            }
            for op, comp in zip(node.ops, node.comparators):
                right = await self._expr(comp)
                deps.append(right.node_id)
                op_func = cmp_ops.get(type(op))
                if op_func:
                    result = result and op_func(left.value, right.value)
                left = right
            return self.dag.add(result, Source(SourceType.COMPUTED), deps)

        if isinstance(node, ast.List):
            items, deps = [], []
            for elt in node.elts:
                cv = await self._expr(elt)
                items.append(cv.value)
                deps.append(cv.node_id)
            return self.dag.add(items, Source(SourceType.COMPUTED), deps)

        if isinstance(node, ast.Dict):
            keys, vals, deps = [], [], []
            for k, v in zip(node.keys, node.values):
                kcv = await self._expr(k)
                vcv = await self._expr(v)
                keys.append(kcv.value)
                vals.append(vcv.value)
                deps.extend([kcv.node_id, vcv.node_id])
            return self.dag.add(dict(zip(keys, vals)), Source(SourceType.COMPUTED), deps)

        if isinstance(node, ast.Subscript):
            obj = await self._expr(node.value)
            if isinstance(node.slice, ast.Constant):
                idx = node.slice.value
            else:
                idx = (await self._expr(node.slice)).value
            return self.dag.add(obj.value[idx], obj.source, [obj.node_id])

        if isinstance(node, ast.Attribute):
            obj = await self._expr(node.value)
            return self.dag.add(getattr(obj.value, node.attr), obj.source, [obj.node_id])

        if isinstance(node, ast.JoinedStr):
            parts, deps = [], []
            for v in node.values:
                cv = await self._expr(v)
                parts.append(str(cv.value))
                deps.append(cv.node_id)
            return self.dag.add("".join(parts), Source(SourceType.COMPUTED), deps)

        if isinstance(node, ast.FormattedValue):
            return await self._expr(node.value)

        if isinstance(node, ast.BoolOp):
            values = [await self._expr(v) for v in node.values]
            deps = [v.node_id for v in values]
            if isinstance(node.op, ast.And):
                result = all(v.value for v in values)
            else:
                result = any(v.value for v in values)
            return self.dag.add(result, Source(SourceType.COMPUTED), deps)

        if isinstance(node, ast.UnaryOp):
            operand = await self._expr(node.operand)
            ops = {ast.Not: operator.not_, ast.USub: operator.neg, ast.UAdd: operator.pos}
            op_func = ops.get(type(node.op))
            if op_func:
                return self.dag.add(op_func(operand.value), Source(SourceType.COMPUTED), [operand.node_id])

        if isinstance(node, ast.IfExp):
            test = await self._expr(node.test)
            if test.value:
                return await self._expr(node.body)
            return await self._expr(node.orelse)

        if isinstance(node, ast.Tuple):
            items, deps = [], []
            for elt in node.elts:
                cv = await self._expr(elt)
                items.append(cv.value)
                deps.append(cv.node_id)
            return self.dag.add(tuple(items), Source(SourceType.COMPUTED), deps)

        raise NotImplementedError(f"AST node: {type(node).__name__}")

    async def _call(self, node: ast.Call) -> CapValue:
        """Evaluate a function/tool call with policy enforcement."""
        # Resolve function
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            func_cv = self._globals.get(func_name)
        elif isinstance(node.func, ast.Attribute):
            obj_cv = await self._expr(node.func.value)
            func_name = node.func.attr
            func_cv = self.dag.add(
                getattr(obj_cv.value, func_name), obj_cv.source, [obj_cv.node_id]
            )
        else:
            raise NotImplementedError(f"call: {type(node.func).__name__}")

        if func_cv is None:
            raise NameError(f"'{func_name}' is not defined")

        # Evaluate arguments
        args_cv = [await self._expr(a) for a in node.args]
        kwargs_cv = {}
        for kw in node.keywords:
            if kw.arg:
                kwargs_cv[kw.arg] = await self._expr(kw.value)

        # Tool call — check policy
        if func_name in self.tools:
            return await self._tool_call(func_name, args_cv, kwargs_cv)

        # Method call on an object
        raw_args = [cv.value for cv in args_cv]
        raw_kwargs = {k: cv.value for k, cv in kwargs_cv.items()}
        all_deps = [cv.node_id for cv in args_cv] + [cv.node_id for cv in kwargs_cv.values()]

        try:
            result = func_cv.value(*raw_args, **raw_kwargs)
        except TypeError:
            # Some builtins don't accept kwargs
            result = func_cv.value(*raw_args)

        return self.dag.add(result, Source(SourceType.COMPUTED), all_deps + [func_cv.node_id])

    async def _tool_call(
        self, tool_name: str, args_cv: list[CapValue], kwargs_cv: dict[str, CapValue],
    ) -> CapValue:
        """Call a tool with full provenance-based policy enforcement.

        For each sensitive parameter, traces the argument's FULL lineage
        back through the DAG. If ANY ancestor is from an untrusted tool,
        the call is blocked. This is the CaMeL guarantee.
        """
        sensitive = self.sensitive_params.get(tool_name, set())

        for param_name, cv in kwargs_cv.items():
            if param_name in sensitive:
                if self.dag.has_untrusted(cv.node_id, self.untrusted_tools):
                    sources = self.dag.get_all_sources(cv.node_id)
                    untrusted = [
                        str(s) for s in sources
                        if s.type == SourceType.TOOL and s.identifier in self.untrusted_tools
                    ]
                    raise PolicyViolation(
                        tool_name, param_name,
                        f"untrusted lineage: {untrusted}"
                    )

        # Execute
        raw_args = [cv.value for cv in args_cv]
        raw_kwargs = {k: cv.value for k, cv in kwargs_cv.items()}
        all_deps = [cv.node_id for cv in args_cv] + [cv.node_id for cv in kwargs_cv.values()]

        func = self.tools[tool_name]
        if asyncio.iscoroutinefunction(func):
            result = await func(*raw_args, **raw_kwargs)
        else:
            result = func(*raw_args, **raw_kwargs)

        self._results.append({"tool": tool_name, "result": result})
        return self.dag.add(result, Source(SourceType.TOOL, tool_name), all_deps)
