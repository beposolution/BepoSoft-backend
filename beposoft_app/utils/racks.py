# views/grv_update.py

from collections import defaultdict

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response

from beposoft_app.models import Products



# -----------------------------
# Rack mutation helpers
# -----------------------------

def _norm_usability(v):
    v = (v or "").strip().lower()
    return v if v else "usable"

def _qty_from_row(row):
    for k in ("quantity", "qty", "rack_quantity", "rack_stock"):
        if k in row:
            try:
                q = int(row.get(k) or 0)
                return max(q, 0)
            except (TypeError, ValueError):
                pass
    return 0

def _key_tuple(row):
    # Key used for coalescing deltas and looking up rack slots
    return (
        row.get("rack_id"),
        row.get("column_name"),
        _norm_usability(row.get("usability")),
    )

def _coalesce(rows, sign=+1):
    acc = defaultdict(int)
    for r in rows or []:
        q = _qty_from_row(r)
        if q <= 0:
            continue
        acc[_key_tuple(r)] += sign * q
    return acc


def mutate_product_rack_stocks(product, add_rows=None, sub_rows=None, debug=True):
    """
    Mutate product.rack_details:
      - add_rows: increments rack_stock for matching slots (creates slot if missing)
      - sub_rows: decrements rack_stock for matching slots (must exist & be sufficient)
    Slots are keyed by (rack_id, column_name, usability).
    """
    add_rows = add_rows or []
    sub_rows = sub_rows or []

    if debug:
        print("\n================= mutate_product_rack_stocks =================")
        print(f"Product ID: {product.pk}, Name: {getattr(product, 'name', '')}")
        print(f"Add rows (raw): {add_rows}")
        print(f"Sub rows (raw): {sub_rows}")

    adds = _coalesce(add_rows, +1)
    subs = _coalesce(sub_rows, -1)

    # Merge adds & subs into a single delta map
    delta_map = defaultdict(int)
    for k, v in adds.items():
        delta_map[k] += v
    for k, v in subs.items():
        delta_map[k] += v  # note: v is negative

    with transaction.atomic():
        # Lock product row
        p = Products.objects.select_for_update().get(pk=product.pk)
        racks = list(p.rack_details or [])

        # Build index for quick lookup
        index = {
            (r.get("rack_id"), r.get("column_name"), _norm_usability(r.get("usability"))): r
            for r in racks
        }

        # Create missing slots only for positive deltas
        for key, d in delta_map.items():
            if key not in index and d > 0:
                rack_id, col, usability = key
                new_slot = {
                    "warehouse": None,         # kept as-is; caller may set defaults
                    "rack_id": rack_id,
                    "rack_name": None,
                    "column_name": col,
                    "usability": usability,
                    "rack_stock": 0,
                    "rack_lock": 0,
                }
                racks.append(new_slot)
                index[key] = new_slot
                if debug:
                    print(f"[CREATE] missing slot {key} for +{d}")

        # Validate subtractions (existing slot + sufficient stock)
        for key, d in delta_map.items():
            pr = index.get(key)
            if not pr:
                if d < 0:
                    raise ValueError(f"Rack not found for key={key} (net {d}).")
                continue
            current = int(pr.get("rack_stock") or 0)
            if current + d < 0:
                raise ValueError(f"Insufficient stock in rack {key}: current {current}, net {d}.")

        # Apply deltas
        changed = False
        for key, d in delta_map.items():
            pr = index.get(key)
            if not pr or d == 0:
                continue
            before = int(pr.get("rack_stock") or 0)
            pr["rack_stock"] = before + d
            changed = True
            if debug:
                action = "ADD" if d > 0 else "SUB"
                print(f"[{action}] {key}: {before} {'+' if d>0 else ''}{d} => {pr['rack_stock']}")

        if changed:
            p.rack_details = racks
            p.save(update_fields=["rack_details"])

            if debug:
                p.refresh_from_db()
                print("\n--- Saved rack state ---")
                for r in p.rack_details:
                    print(
                        f"rack_id={r.get('rack_id')}, col={r.get('column_name')}, "
                        f"usability={r.get('usability')}, stock={int(r.get('rack_stock') or 0)}, "
                        f"lock={int(r.get('rack_lock') or 0)}"
                    )
                print("=============================================================\n")


# -----------------------------
# GRV Update View
# -----------------------------
