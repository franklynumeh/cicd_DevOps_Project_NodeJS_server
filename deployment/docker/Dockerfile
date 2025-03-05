FROM nvidia/cuda:12.1.0-runtime-ubuntu22.04

WORKDIR /app

RUN apt-get update && apt-get install -y python3-pip && \
  rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir jupyterlab
RUN pip3 install --upgrade pip setuptools wheel
RUN pip3 install torch==2.2.1+cu118 -f https://download.pytorch.org/whl/torch_stable.html
RUN pip3 install transformers

CMD ["jupyter-lab", "--ip=0.0.0.0", "--no-browser", "--allow-root"]
