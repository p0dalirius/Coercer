.PHONY : all clean build upload

all: install clean

clean:
	@rm -rf `find ./ -type d -name "*__pycache__"`
	@rm -rf ./build/ ./dist/ ./coercer.egg-info/

docs:
	@python3 -m pip install pdoc
	@echo "[$(shell date)] Generating docs ..."
	@python3 -m pdoc -d markdown -o ./documentation/ ./coercer/
	@echo "[$(shell date)] Done!"

install: build
	python3 -m pip uninstall coercer --break-system-packages --yes
	python3 setup.py install

build:
	python3 setup.py sdist bdist_wheel

upload: build
	twine upload dist/*
