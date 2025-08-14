# beposoft_app/utils/racks.py
from decimal import Decimal

class RackAllocationError(Exception):
    pass

def allocate_racks_for_quantity(product, quantity_needed: int):
    """
    Returns a list of allocations: [{"rack_id":..., "column_name":..., "quantity":...}, ...]
    Will raise RackAllocationError if not enough available across usable racks.
    """
    racks = product.rack_details or []
    need = int(quantity_needed)
    if need <= 0:
        return []

    allocations = []
    total_available = 0

    # Greedy FIFO by the order stored in product.rack_details
    for r in racks:
        if r.get("usability") != "usable":
            continue
        rack_stock = int(r.get("rack_stock", 0) or 0)
        rack_lock  = int(r.get("rack_lock", 0) or 0)
        available  = max(0, rack_stock - rack_lock)
        if available <= 0:
            continue

        total_available += available
        if need <= 0:
            break

        take = min(need, available)
        if take > 0:
            allocations.append({
                "rack_id":     r.get("rack_id"),
                "column_name": r.get("column_name"),
                "quantity":    take
            })
            need -= take

    if need > 0:
        raise RackAllocationError(
            f"Insufficient rack availability for product {product.pk}: "
            f"need {quantity_needed}, available {total_available}"
        )

    return allocations
