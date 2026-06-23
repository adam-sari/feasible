# Datacenter Capacity & Maintenance SOP (synthetic; 48 MW colo hall)

## 1. Facility
The facility is a single 48 MW hall fed by redundant UPS feeds and cooling paths.
Racks draw a mixed 8 / 40 / 132 kW fleet across two independent fault domains.

## 2. Redundancy floor
The facility must at all times maintain N+1 redundancy on every cooling path and 2N on every UPS feed; maintenance shall not reduce available redundant capacity below the N+1 floor.

## 3. Power caps
Every feed must keep its aggregate rack draw within the certified feed cap, and no single rack may exceed its per-member share of that cap.

## 4. Maintenance windows
Maintenance tasks must not be scheduled inside a posted change-freeze window on the path under maintenance.

## 5. Fault-domain anti-affinity
Replicas of a redundant service must not be placed in the same power or cooling fault domain.

## 6. Commissioning
Commissioning acceleration and stranded-power efficiency are preferred objectives, but never at the expense of the redundancy floor.
