"""Setup script for Socket Sender."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="socket-sender",
    version="1.0.0",
    author="Özgür Ş.",
    description="A versatile network socket sender for TCP and UDP protocols",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/02gur/Socket-Sender",
    py_modules=["socket_sender"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "socket-sender=socket_sender:main",
        ],
    },
)
