import csv
csv.field_size_limit(2**31 - 1)  # carved strings can be long
src, dst = r"E:\tmp\attributed.csv", r"E:\tmp\attributed.clean.csv"
with open(src, "r", newline="", encoding="utf-8", errors="replace") as f, \
     open(dst, "w", newline="", encoding="utf-8") as o:
    reader, writer = csv.reader(f), csv.writer(o, lineterminator="\n")
    drop = False
    n = 0
    for i, row in enumerate(reader):
        cells = [c.replace("\r", " ").replace("\n", " ").rstrip() for c in row]
        if i == 0 and cells[:1] == ["TreeDepth"]:
            drop = True
        writer.writerow(cells[1:] if drop else cells)
        n += 1
    print(f"{n:,} records -> {dst}")
