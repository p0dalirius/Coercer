.PHONY : all clean build upload

all: install clean

clean:
	@rm -rf `find ./ -type d -name "*__pycache__"`
	@rm -rf ./build/ ./dist/ ./coercer.egg-info/

install:
	python3 setup.py install

build:
	python3 setup.py sdist bdist_wheel

upload:
	python3 setup.py sdist upload
