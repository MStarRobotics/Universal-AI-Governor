#!/usr/bin/env python3
"""
Setup script for Universal AI Governor Python SDK
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="universal-ai-governor",
    version="1.0.0",
    author="Sourav Rajak",
    author_email="morningstar.xcd@gmail.com",
    description="Python SDK for Universal AI Governor",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/MStarRobotics/Universal-AI-Governor",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "pydantic>=2.0.0",
        "httpx>=0.24.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ai-governor=ai_governor.cli:main",
        ],
    },
)
