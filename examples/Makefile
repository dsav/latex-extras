BUILDER = latexmk
BUILD_FLAGS = -pdf -xelatex -shell-escape -interaction=nonstopmode >/dev/null 2>&1
LOG_READER = rubber-info
LOG_READER_FLAGS = --check

# Make sure to add 'pyg' to @generated_exts option of latexmk to remove .pyg files when cleaning.
# Set $bibtex_use option to 2 in order to remove generated .bbl files when cleaning.
SOFT_CLEAN_FLAGS = -c
CLEAN_FLAGS = -C


all: lab article gost-article

lab: lab.tex
	@echo "Processing lab.tex..."
	@$(BUILDER) $(BUILD_FLAGS) lab.tex; \
		$(LOG_READER) --errors lab.log; \
		$(LOG_READER) --warnings lab.log; \
		$(LOG_READER) --boxes lab.log

article: article.tex
	@echo "Processing article.tex..."
	@$(BUILDER) $(BUILD_FLAGS) article.tex; \
		$(LOG_READER) --errors article.log; \
		$(LOG_READER) --warnings article.log; \
		$(LOG_READER) --boxes article.log

gost-article: gost-article.tex
	@echo "Processing gost-article.tex..."
	@$(BUILDER) $(BUILD_FLAGS) gost-article.tex; \
		$(LOG_READER) --errors gost-article.log; \
		$(LOG_READER) --warnings gost-article.log; \
		$(LOG_READER) --boxes gost-article.log

soft-clean:
	$(BUILDER) $(SOFT_CLEAN_FLAGS)

clean:
	$(BUILDER) $(CLEAN_FLAGS)
