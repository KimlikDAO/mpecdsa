use std::io;
use std::error;
use std::fmt;
use std::string::String;

#[derive(Debug)]
pub struct ProofError {
	descstring: String
}

#[derive(Debug)]
pub struct GeneralError {
	descstring: String
}

impl GeneralError {
	pub fn new(descstring: &str) -> GeneralError {
		GeneralError {
			descstring: String::from(descstring)
		}
	}
}

impl ProofError {
	pub fn new(descstring: &str) -> ProofError {
		ProofError {
			descstring: String::from(descstring)
		}
	}
}

impl error::Error for ProofError {
	fn description(&self) -> &str {
		"Proof Error"
	}
}

impl error::Error for GeneralError {
	fn description(&self) -> &str {
		"General Error"
	}
}

impl fmt::Display for ProofError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.descstring.as_str())
	}
}

impl fmt::Display for GeneralError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.descstring.as_str())
	}
}

#[derive(Debug)]
pub enum MPECDSAError {
	General(GeneralError),
	Proof(ProofError),
	Io(io::Error),
}

impl fmt::Display for MPECDSAError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			MPECDSAError::Io(ref err) => write!(f, "IO Error: {}", err),
			MPECDSAError::Proof(ref err) => write!(f, "Proof Error: {}", err),
			MPECDSAError::General(ref err) => write!(f, "General Error: {}", err),
		}
	}
}

impl error::Error for MPECDSAError {
	/*fn description(&self) -> &str {
		match *self {
			MPECDSAError::Io(ref err) => err.description(),
			MPECDSAError::Proof(ref err) => err.description(),
			MPECDSAError::General(ref err) => err.description(),
		}
	}*/

	fn cause(&self) -> Option<&dyn error::Error> {
		match *self {
			MPECDSAError::Io(ref err) => Some(err),
			MPECDSAError::Proof(ref err) => Some(err),
			MPECDSAError::General(ref err) => Some(err)
		}
	}
}

impl From<io::Error> for MPECDSAError {
	fn from(err: io::Error) -> MPECDSAError {
		MPECDSAError::Io(err)
	}
}

impl From<ProofError> for MPECDSAError {
	fn from(err: ProofError) -> MPECDSAError {
		MPECDSAError::Proof(err)
	}
}

impl From<GeneralError> for MPECDSAError {
	fn from(err: GeneralError) -> MPECDSAError {
		MPECDSAError::General(err)
	}
}