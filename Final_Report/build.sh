#!/bin/bash
rm -f report.aux report.bbl report.blg report.fdb_latexmk report.fls report.log report.out report.pdf
latexmk -pdf report.tex
