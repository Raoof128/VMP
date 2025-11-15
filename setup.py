"""
VMP Setup Configuration
For package installation and development
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vmp",
    version="1.0.0",
    author="Raouf",
    author_email="your.email@example.com",
    description="Vulnerability Management Pipeline with intelligent risk prioritization",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Raoof128/VMP",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.1",
            "black>=23.12.0",
            "flake8>=6.1.0",
            "mypy>=1.7.1",
            "isort>=5.13.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vmp-api=src.api.main:run",
            "vmp-demo=scripts.demo:main",
            "vmp-load-data=scripts.load_sample_data:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
