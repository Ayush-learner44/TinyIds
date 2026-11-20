"""Cuts the 3 TikZ diagrams out of TinyIDS_ML_Explained.tex into standalone .tex files (for the slides)."""
from pathlib import Path

HERE = Path(__file__).resolve().parent
src = (HERE.parents[1] / "evaluation_matrices" / "TinyIDS_ML_Explained.tex").read_text(encoding="utf-8")
pre = src[src.index("% ---- colours of the system diagrams"):src.index("\\begin{document}")]
BEGIN, END = "\\begin{tikzpicture}", "\\end{tikzpicture}"
pics, pos = [], 0
while True:
    a = src.find(BEGIN, pos)
    if a < 0:
        break
    b = src.index(END, a) + len(END)
    pics.append(src[a:b])
    pos = b
head = ("\\documentclass[border=8pt]{standalone}\n\\usepackage[T1]{fontenc}\\usepackage{lmodern}\\usepackage{amsmath}"
        "\\usepackage[dvipsnames]{xcolor}\n\\usepackage{tikz}\\usetikzlibrary{positioning,arrows.meta,fit,backgrounds,"
        "calc,shapes.geometric}\n")
for name, pic in zip(["hld", "topics", "detector"], pics):
    (HERE / f"{name}.tex").write_text(head + pre + "\\begin{document}\n" + pic + "\n\\end{document}\n", encoding="utf-8")
print(len(pics), "pictures")
