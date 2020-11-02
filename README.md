# study-project

<div align="center">

[![Build status](https://github.com/lucasiscovici/study-project/workflows/build/badge.svg?branch=master&event=push)](https://github.com/lucasiscovici/study-project/actions?query=workflow%3Abuild)
[![Python Version](https://img.shields.io/pypi/pyversions/study-project.svg)](https://pypi.org/project/study-project/)
[![Dependencies Status](https://img.shields.io/badge/dependencies-up%20to%20date-brightgreen.svg)](https://github.com/lucasiscovici/study-project/pulls?utf8=%E2%9C%93&q=is%3Apr%20author%3Aapp%2Fdependabot)

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security: bandit](https://img.shields.io/badge/security-bandit-green.svg)](https://github.com/PyCQA/bandit)
[![Pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/lucasiscovici/study-project/blob/master/.pre-commit-config.yaml)
[![Semantic Versions](https://img.shields.io/badge/%F0%9F%9A%80-semantic%20versions-informational.svg)](https://github.com/lucasiscovici/study-project/releases)
[![License](https://img.shields.io/github/license/lucasiscovici/study-project)](https://github.com/lucasiscovici/study-project/blob/master/LICENSE)

DataScience and ML MAnagement
</div>

# CLI

```bash
curl -L -s https://tinyurl.com/study-project-init | sh -s my-project
#with alias
alias study-project-init="curl -L -s https://tinyurl.com/study-project-init | sh -s "
study-project-init my-project
``` 
This command will **init**:
- add directory my-project
- check if image 'studyproject/scipy-notebook' is up-to-date
	- pull if not
- run container in port from 8888 to 8898 (check witch port is open)

```bash
study-project-init my-project --open 
```

This command will 
	- **init** if need
	- open the jupyter notebook in your browser
	- the token is : study-project



## 🛡 License

[![License](https://img.shields.io/github/license/lucasiscovici/study-project)](https://github.com/lucasiscovici/study-project/blob/master/LICENSE)

This project is licensed under the terms of the `MIT` license. See [LICENSE](https://github.com/lucasiscovici/study-project/blob/master/LICENSE) for more details.

## 📃 Citation

```
@misc{study-project,
  author = {study-project},
  title = {DataScience and ML MAnagement},
  year = {2020},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://github.com/lucasiscovici/study-project}}
}
```

## Credits

This project was generated with [`python-package-template`](https://github.com/TezRomacH/python-package-template).
