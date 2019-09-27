set -e
set +x

for VER in 2.7 3.4 3.5 3.6 3.7; do
    PYTHON=python${VER}
    PIP=pip${VER}
    VENV=venv_${VER}

    # update pip for newer TLS support
    curl https://bootstrap.pypa.io/get-pip.py | ${PYTHON}
    ${PIP} install --upgrade pip

    # update virtualenv
    ${PIP} install --upgrade virtualenv
    virtualenv -p ${PYTHON} ${VENV}
    . ./${VENV}/bin/activate

    # install cffi module
    ${PYTHON} -m pip install cffi

    ${PYTHON} setup.py bdist_wheel
    ${PIP} install -r requirements/test.txt
    set +e
    ${PIP} uninstall -y wolfssl
    set -e
    ${PIP} install wolfssl --no-index -f dist
    rm -rf tests/__pycache__
    py.test tests
    deactivate
done
