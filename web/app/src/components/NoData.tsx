/** Explicit "no data" affordance for facade fields that are null until a later
 * track lands (datacenter units/groups/capacity, the Gemini draft). Never a blank. */
export function NoData({ label }: { label: string }) {
  return (
    <span className="nodata" data-testid="nodata">
      {label} — no data (lands with a later track)
    </span>
  );
}
