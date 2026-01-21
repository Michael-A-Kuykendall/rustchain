use crate::core::error::RustChainError;

pub trait Embedder: Send + Sync {
    fn embed(&self, text: &str) -> Result<Vec<f32>, RustChainError>;
    fn name(&self) -> &'static str;
    fn dimensions(&self) -> usize;
}

pub enum EmbedderBackend {
    Static(Box<dyn Embedder>),
    Onnx(Box<dyn Embedder>),
    Remote(Box<dyn Embedder>),
}

impl EmbedderBackend {
    pub fn embed(&self, input: &str) -> Result<Vec<f32>, RustChainError> {
        match self {
            Self::Static(backend) => backend.embed(input),
            Self::Onnx(backend) => backend.embed(input),
            Self::Remote(backend) => backend.embed(input),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Static(b) => b.name(),
            Self::Onnx(b) => b.name(),
            Self::Remote(b) => b.name(),
        }
    }

    pub fn dimensions(&self) -> usize {
        match self {
            Self::Static(b) => b.dimensions(),
            Self::Onnx(b) => b.dimensions(),
            Self::Remote(b) => b.dimensions(),
        }
    }
}
