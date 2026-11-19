"""Offline permission-graph rendering (no database required).

Renders the same graph Neo4j Browser would show, as a PNG. Layout mirrors
the data model: principals on the left, groups and policies in the middle,
actions on the right — so every permission path reads left-to-right:

    (Principal) -MEMBER_OF-> (Group) -GRANTED-> (Policy) -ALLOWS-> (Action)
    (Principal) -------------------GRANTED/CAN_USE/INVOKED-------------> (Action)

Color semantics (README hero image):
* green action  — used (INVOKED)
* red action    — granted but never used (CAN_USE with used=false)
* orange action — ATTEMPTED (every observed call failed)
* red big node  — wildcard blast radius (e.g. ``*`` = all 20,455 actions)
* purple edges  — hidden paths through group membership

A real snapshot yields tens of thousands of CAN_USE edges, so the renderer
shows a *focused* subgraph: all topology nodes, used/attempted actions, and
each principal's highest-risk unused actions (capped). The full graph lives
in Neo4j.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .model import GraphModel

__all__ = ["render_graph"]

LOGGER = logging.getLogger(__name__)

# Palette (RGB)
BG = (24, 26, 32)
FG = (210, 214, 224)
USER = (97, 175, 239)
ROLE = (229, 192, 123)
GROUP_C = (189, 147, 249)
POLICY = (92, 207, 230)
USED = (152, 195, 121)
UNUSED = (224, 108, 117)
ATTEMPT = (229, 152, 102)
EDGE = (90, 96, 110)
EDGE_HIDDEN = (189, 147, 249)

_PER_PRINCIPAL_UNUSED = 6
_COL_PRINCIPAL = 1.2
_COL_MIDDLE = 4.6
_COL_ACTION = 8.6
# Right action lane offset from _COL_ACTION. Wide enough that two-line
# labels (see _wrap_action_label) clear both lanes and the figure edge —
# calibrated in scripts/measure_label_overlap.py.
_ACTION_LANE_GAP = 2.1
# Labels longer than this wrap to a second line instead of spilling across
# lanes (Azure names routinely pass 40 chars; AWS service:action stays short).
_LABEL_WRAP_LIMIT = 26
_X_MAX = 12.6


def _wrap_action_label(label: str, limit: int = _LABEL_WRAP_LIMIT) -> str:
    """Break long action labels into two lines: namespace / operation.

    Azure names read ``microsoft.<service>/<resource>/<op>`` and AWS reads
    ``service:action``; drawn as one line the long ones spill from the left
    action lane onto the right lane's nodes. Wrapping after the namespace
    keeps the full name readable (no truncation) and fits both lanes.
    """
    if len(label) <= limit or "\n" in label:
        return label
    head, sep, tail = label.partition("/")
    if not sep:
        head, sep, tail = label.partition(":")
    if sep and tail and len(head) <= limit:
        return f"{head}{sep}\n{tail}"
    if " " in label[:limit]:  # multi-word summary (wildcard counts): break at a space
        cut = label[:limit].rfind(" ")
        return f"{label[:cut]}\n{label[cut + 1 :]}"
    return f"{label[: limit - 1]}-\n{label[limit - 1 :]}"  # single long token: hyphenate


def render_graph(
    model: GraphModel,
    output: Path,
    *,
    width_px: int = 1500,
    unused_per_principal: int = _PER_PRINCIPAL_UNUSED,
) -> Path:
    """Render a focused permission-graph view to ``output`` (PNG).

    Returns:
        The output path (also written), so callers can chain checks.
    """
    import matplotlib.font_manager as fm

    fm.fontManager.addfont("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

    plt.rcParams["font.family"] = "DejaVu Sans"

    # ---- select the focused subgraph
    principals = [n for n in model.nodes if "Principal" in n.labels]
    groups = [n for n in model.nodes if "Group" in n.labels]
    policies = [n for n in model.nodes if "Policy" in n.labels]

    show_actions: dict[str, str] = {}  # action key -> kind (used/attempted/unused/wildcard)
    for edge in model.edges_by_type("INVOKED"):
        show_actions[edge.target] = "used"
    for edge in model.edges_by_type("ATTEMPTED"):
        show_actions.setdefault(edge.target, "attempted")
    per_principal: dict[str, int] = {}
    for edge in model.edges_by_type("CAN_USE"):
        if edge.target in show_actions:
            continue
        if edge.props.get("used"):
            show_actions.setdefault(edge.target, "used")
            continue
        count = per_principal.get(edge.source, 0)
        if count < unused_per_principal:
            per_principal[edge.source] = count + 1
            show_actions.setdefault(edge.target, "unused")
    for edge in model.edges_by_type("ALLOWS"):
        if edge.target.endswith(":*") or edge.target == "action:*":
            show_actions.setdefault(edge.target, "wildcard")

    # ---- positions: three columns, principals spread full height
    def spread(items: list[Any], x: float, y_min: float, y_max: float) -> dict[str, tuple[float, float]]:
        n = len(items)
        if n == 0:
            return {}
        if n == 1:
            return {items[0].key: (x, (y_min + y_max) / 2)}
        step = (y_max - y_min) / (n - 1)
        return {item.key: (x, y_max - i * step) for i, item in enumerate(items)}

    action_nodes = sorted(
        (n for n in model.nodes if n.key in show_actions),
        key=lambda n: (show_actions[n.key] != "used", show_actions[n.key] != "attempted", n.key),
    )

    pos: dict[str, tuple[float, float]] = {}
    pos.update(spread(principals, _COL_PRINCIPAL, 0.8, 8.6))
    pos.update(spread(groups, _COL_MIDDLE - 1.15, 5.2, 7.6))
    pos.update(spread(policies, _COL_MIDDLE + 0.95, 1.0, 7.9))
    # actions in two side-by-side lanes; lane height scales with load so
    # labels never collide on dense graphs
    half = (len(action_nodes) + 1) // 2
    left_lane, right_lane = action_nodes[:half], action_nodes[half:]
    lane_top = 8.9 if max(len(left_lane), len(right_lane)) <= 14 else 9.1
    pos.update(spread(left_lane, _COL_ACTION, 0.4, lane_top))
    pos.update(spread(right_lane, _COL_ACTION + _ACTION_LANE_GAP, 0.4, lane_top))

    def hexc(rgb: tuple) -> str:
        return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"

    fig, ax = plt.subplots(figsize=(width_px / 110, 8.9), dpi=110)
    fig.patch.set_facecolor(hexc(BG))
    ax.set_facecolor(hexc(BG))
    ax.set_xlim(0, _X_MAX)
    ax.set_ylim(-0.5, 10.5)
    ax.axis("off")

    # ---- column captions
    for x, caption in (
        (_COL_PRINCIPAL, "PRINCIPALS"),
        (_COL_MIDDLE, "GROUPS · POLICIES"),
        (_COL_ACTION + _ACTION_LANE_GAP / 2, "ACTIONS (usage-colored)"),
    ):
        ax.text(
            x, 9.42, caption, ha="center", fontsize=8, color=hexc(EDGE), weight="bold", family="DejaVu Sans"
        )

    # ---- edges (drawn first, nodes on top)
    def arrow(src: str, dst: str, color: str, lw: float, alpha: float, style: str = "-") -> None:
        if src not in pos or dst not in pos:
            return
        ax.annotate(
            "",
            xy=pos[dst],
            xytext=pos[src],
            arrowprops=dict(
                arrowstyle="->,head_width=0.25,head_length=0.4",
                lw=lw,
                alpha=alpha,
                color=color,
                shrinkA=10,
                shrinkB=8,
                linestyle=style,
            ),
        )

    for edge in model.edges:
        kind = None
        if edge.type == "MEMBER_OF":
            kind = (EDGE_HIDDEN, 1.2, 0.8)
        elif edge.type == "GRANTED":
            hidden = bool(edge.props.get("via_group"))
            kind = (EDGE_HIDDEN if hidden else EDGE, 1.2, 0.7)
        elif edge.type == "ALLOWS":
            kind = (EDGE, 1.0, 0.6)
        elif edge.type == "INVOKED":
            kind = (USED, 1.8, 0.95)
        elif edge.type == "ATTEMPTED":
            kind = (ATTEMPT, 1.8, 0.95)
        elif edge.type == "CAN_USE" and edge.target in show_actions:
            kind = (UNUSED, 1.1, 0.55)
        if kind:
            arrow(edge.source, edge.target, hexc(kind[0]), kind[1], kind[2])

    # ---- nodes
    for node in model.nodes:
        if node.key not in pos:
            continue
        x, y = pos[node.key]
        if "Principal" in node.labels:
            color, size = (ROLE if "Role" in node.labels else USER), 300
        elif "Group" in node.labels:
            color, size = GROUP_C, 260
        elif "Policy" in node.labels:
            color, size = POLICY, 260
        else:
            usage_kind = show_actions.get(node.key, "unused")
            color = {"used": USED, "attempted": ATTEMPT}.get(usage_kind, UNUSED)
            size = 210
            if usage_kind == "wildcard":
                size = 420
        ax.scatter([x], [y], s=size, c=hexc(color), edgecolors="white", linewidths=0.7, zorder=3)

    # ---- labels
    for node in model.nodes:
        if node.key not in pos:
            continue
        x, y = pos[node.key]
        if "Principal" in node.labels:
            suffix = " (role)" if "Role" in node.labels else ""
            ax.text(
                x,
                y - 0.34,
                f"{node.props.get('name', '')}{suffix}\nrisk {node.props.get('risk_score', 0):.0f}",
                ha="center",
                va="top",
                fontsize=8.4,
                color="white",
                zorder=4,
            )
        elif "Group" in node.labels:
            ax.text(
                x + 0.05,
                y + 0.22,
                f"group:{node.props.get('name', '')}",
                ha="center",
                fontsize=7.6,
                color=hexc(GROUP_C),
                zorder=4,
            )
        elif "Policy" in node.labels:
            ax.text(
                x,
                y - 0.24,
                str(node.props.get("name", "")),
                ha="center",
                va="top",
                fontsize=7.6,
                color=hexc(POLICY),
                zorder=4,
            )
        else:
            action = node.props.get("action", node.key)
            if node.key == "action:*":
                count = node.props.get("expansion_size", "?")
                label = f"*  →  ALL {count:,} actions"
            elif "*" in action:
                label = f"{action}  ({node.props.get('expansion_size', '?')} actions)"
            else:
                label = action
            label = _wrap_action_label(label)
            usage_kind = show_actions.get(node.key, "unused")
            ax.text(
                x + 0.16,
                y,
                label,
                ha="left",
                va="center",
                fontsize=7.4,
                color=hexc(USED if usage_kind == "used" else FG),
                zorder=4,
                weight="bold" if usage_kind == "used" else "normal",
            )

    # ---- title & legend (kept clear of the column captions below)
    ax.text(
        0.15,
        10.15,
        "permtrim — IAM permission graph",
        fontsize=13.5,
        color="white",
        weight="bold",
        va="center",
    )
    ax.text(
        0.15,
        9.75,
        f"account {model.account_id} · {model.lookback_days}-day window · "
        "focused view: used + top-unused + wildcard blast radius",
        fontsize=8.2,
        color=hexc(FG),
        alpha=0.85,
        va="center",
    )

    legend_items = [
        Line2D([], [], marker="o", ls="", mfc=hexc(USER), mec="white", ms=8, label="User"),
        Line2D([], [], marker="o", ls="", mfc=hexc(ROLE), mec="white", ms=8, label="Role"),
        Line2D([], [], marker="o", ls="", mfc=hexc(GROUP_C), mec="white", ms=8, label="Group"),
        Line2D([], [], marker="o", ls="", mfc=hexc(POLICY), mec="white", ms=8, label="Policy"),
        Line2D([], [], marker="o", ls="", mfc=hexc(USED), mec="white", ms=8, label="Used action"),
        Line2D([], [], marker="o", ls="", mfc=hexc(UNUSED), mec="white", ms=8, label="Granted, never used"),
        Line2D(
            [], [], marker="o", ls="", mfc=hexc(ATTEMPT), mec="white", ms=8, label="Attempted, all denied"
        ),
        Line2D([], [], color=hexc(EDGE_HIDDEN), lw=1.5, label="Hidden path via group"),
    ]
    ax.legend(
        handles=legend_items,
        loc="lower left",
        frameon=True,
        fontsize=7.4,
        facecolor="#20232a",
        edgecolor=hexc(EDGE),
        labelcolor=hexc(FG),
        ncol=4,
        bbox_to_anchor=(0.0, -0.02),
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, facecolor=fig.get_facecolor())
    plt.close(fig)
    LOGGER.info("Rendered graph to %s", output)
    return output
