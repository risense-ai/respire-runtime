# BGE small Chinese v1.5 preset

Upstream: [BAAI/bge-small-zh-v1.5](https://huggingface.co/BAAI/bge-small-zh-v1.5).
ONNX conversion: [Xenova/bge-small-zh-v1.5](https://huggingface.co/Xenova/bge-small-zh-v1.5/tree/75c43b069aac4d136ba6bc1122f995fedcfd2781).
MIT license: see the included `FlagEmbedding-LICENSE.txt`.

The preset uses 512-dimensional CLS embeddings, L2 normalization, a 512-token
window and the upstream Chinese retrieval instruction as its query prefix. Documents have
no prefix. Quantized weights are 24,010,842 bytes with SHA-256
`15b717c382bcb518ba457b93ea6850ede7f4f1cd8937454aa06972366cd19bcc`.
The tokenizer is 439,125 bytes with SHA-256
`48cea5d44424912a6fd1ea647bf4fe50b55ab8b1e5879c3275f80e339e8fae26`.
