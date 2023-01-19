use ::ccart::{pack_stream, default_digesters, unpack_stream};
use pyo3::types::PyModule;
use pyo3::{PyResult, pymodule, Python, wrap_pyfunction, pyfunction};
use pyo3::exceptions::PyValueError;


#[pyfunction]
fn pack_file_default(
    input_path: &str,
    output_path: &str,
    header_json: &str,
) -> PyResult<()> {
    // Open input file
    let input_file = std::fs::File::open(input_path)?;
    let input_file = std::io::BufReader::new(input_file);

    // Open output file
    let output_file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(output_path)?;
    let output_file = std::io::BufWriter::new(output_file);

    // Parse header json
    let header = match serde_json::from_str(header_json){
        Ok(header) => header,
        Err(_) => return Err(PyValueError::new_err(":(")),
    };

    // Process stream
    pack_stream(
        input_file,
        output_file,
        Some(header),
        None,
        default_digesters(),
        None
    )?;

    return Ok(())
}

#[pyfunction]
pub fn unpack_file(
    input_path: &str,
    output_path: &str,
) -> PyResult<()> {
    // Open input file
    let input_file = std::fs::File::open(input_path)?;
    let input_file = std::io::BufReader::new(input_file);

    // Open output file
    let output_file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(output_path)?;
    let output_file = std::io::BufWriter::new(output_file);

    // Process stream
    let result = unpack_stream(
        input_file,
        output_file,
        None
    )?;

    Ok(())
}

#[pymodule]
fn ccart(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pack_file_default, m)?)?;
    m.add_function(wrap_pyfunction!(unpack_file, m)?)?;
    Ok(())
}

