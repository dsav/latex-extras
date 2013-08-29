BUILDER = latexmk
BUILD_FLAGS = -pdf -xelatex -shell-escape

# Make sure to add 'pyg' to @generated_exts option of latexmk to remove .pyg files when cleaning.
# Set $bibtex_use option to 2 in order to remove generated .bbl files when cleaning.
SOFT_CLEAN_FLAGS = -c
CLEAN_FLAGS = -C


all: lab article gost-article

lab:
	$(BUILDER) $(BUILD_FLAGS) lab.tex

article:
	$(BUILDER) $(BUILD_FLAGS) article.tex

gost-article:
	$(BUILDER) $(BUILD_FLAGS) gost-article.tex

soft-clean:
	$(BUILDER) $(SOFT_CLEAN_FLAGS)

clean:
	$(BUILDER) $(CLEAN_FLAGS)
