.PHONY : all clean build upload

all: install clean

clean:
	@rm -rf `find ./ -type d -name "*__pycache__"`
	@rm -rf ./build/ ./dist/ ./coercer.egg-info/

docs:
	@python3 -m pip install pdoc --break-system-packages
	@echo "[$(shell date)] Generating docs ..."
	@PDOC_ALLOW_EXEC=1 python3 -m pdoc -d markdown -o ./documentation/ ./coercer/
	@echo "[$(shell date)] Done!"

install: build
	pip install . --break-system-packages

build:
	python3 -m pip uninstall coercer --yes --break-system-packages
	python3 -m pip install .[build] --break-system-packages
	python3 -m build --wheel

upload: build
	python3 -m pip install .[twine] --break-system-packages
	python3 -m twine upload dist/*


lint:
	@echo "[$(shell date)] Installing linting tools ..."
	@python3 -m pip install flake8 black isort --break-system-packages
	@echo "[$(shell date)] Running flake8 linting ..."
	@python3 -m flake8 coercer/ --exclude=coercer/ext --max-line-length=88 --extend-ignore=E501,E203
	@echo "[$(shell date)] Running black code formatting check ..."
	@python3 -m black --check --diff coercer/ --exclude 'coercer/ext'
	@echo "[$(shell date)] Running isort import sorting check ..."
	@python3 -m isort --check-only --diff coercer/ --skip coercer/ext
	@echo "[$(shell date)] Linting completed!"

lint-fix:
	@echo "[$(shell date)] Installing linting tools ..."
	@python3 -m pip install flake8 black isort --break-system-packages
	@echo "[$(shell date)] Running black to fix formatting issues ..."
	@python3 -m black coercer/ --exclude 'coercer/ext'
	@echo "[$(shell date)] Running isort to fix import sorting ..."
	@python3 -m isort coercer/ --skip coercer/ext
	@echo "[$(shell date)] Running flake8 to check remaining issues ..."
	@python3 -m flake8 coercer/ --exclude=coercer/ext --max-line-length=88 --extend-ignore=E501,E203
	@echo "[$(shell date)] Code formatting fixes completed!"