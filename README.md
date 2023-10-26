# StegaCode

Enhancing Information Security through Swift and Dependable Digital Image Steganography.

StegaCode is an open-source steganography tool written in Rust. It enables the encoding and decoding of information within images, providing a secure method for hiding sensitive data.

## Table of Contents

- [StegaCode](#stegacode)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Examples](#examples)
  - [Contributing](#contributing)
  - [License](#license)

## Introduction

StegaCode is a powerful steganography tool that uses image files as cover mediums to hide data. With StegaCode, you can encode any type of file into an image. The resulting image appears regular and can be opened and viewed like any other image. However, the encoded data remains hidden until it is extracted using StegaCode's decoding functionality.

StegaCode provides a command-line interface (CLI) that allows for easy integration into your workflow. The CLI provides options for encoding and decoding data, specifying the input image, data to be hidden, and output file.

## Installation

To use StegaCode, you need to have the Rust programming language installed on your system. If you haven't already, you can download and install Rust from the official website: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)

Once Rust is installed, you can clone the StegaCode repository from GitHub:

```bash
git clone https://github.com/arncv/stegacode.git
```

Navigate to the cloned directory:

```bash
cd stegacode
```

Build the project:

```bash
cargo build --release
```

## Usage

```bash
stegacode [SUBCOMMAND]
```

StegaCode supports the following subcommands:

- `encode`: Encodes data into an image.
- `decode`: Decodes data from an image.

For more details on each subcommand, you can use the `--help` flag. For example:

```bash
stegacode encode --help
```

## Examples

**Encoding Data:**

To encode data into an image, you can use the `encode` subcommand. Provide the path to the input image, data file, and output file name or path using command-line options.

```bash
stegacode encode  --file secret_data.txt --image cover_image.png --output encoded_image.png
```

This will encode the data from `secret_data.txt` into the `cover_image.png` and save the resulting image as `encoded_image.png`.

**Decoding Data:**

To decode data from an image, you can use the `decode` subcommand. Provide the path to the encoded image and optionally specify the output file name or path.

```bash
stegacode decode --image encoded_image.png 
```

This will decode the data from `encoded_image.png` and save it as `secret.txt`.

## Contributing

Contributions to StegaCode are welcome! If you find any issues or have suggestions for improvements, please open an issue on GitHub or submit a pull request.

To contribute to the project, follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes and push them to your fork.
4. Submit a pull request explaining your changes.

## License

StegaCode is released under the [MIT License](LICENSE). Feel free to use, modify, and distribute it.
