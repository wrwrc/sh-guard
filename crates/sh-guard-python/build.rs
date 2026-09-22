fn main() {
    // macOS extension modules resolve CPython symbols at load time; without
    // these linker args `cargo build` fails with undefined `_Py*` symbols.
    pyo3_build_config::add_extension_module_link_args();
}
