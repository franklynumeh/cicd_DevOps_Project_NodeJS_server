FROM nvidia/cuda:12.1.0-runtime-ubuntu22.04

WORKDIR /app

RUN apt-get update && apt-get install -y python3-pip && \
  rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir jupyterlab
RUN pip3 install --upgrade pip setuptools wheel
RUN pip3 install torch==2.2.1+cu118 -f https://download.pytorch.org/whl/torch_stable.html
RUN pip3 install transformers


COPY deployment/jupyter-cms-ui/dist/templates_cms /usr/local/share/jupyterhub/templates_cms/

COPY deployment/jupyter-cms-ui/dist/static/external /usr/local/share/jupyterhub/static/external/

COPY  deployment/jupyter-cms-ui/jupyterhub_config.py /srv/jupyterhub/jupyterhub_config.py

RUN chown -R jovyan:jovyan /usr/local/share/jupyterhub/

CMD ["jupyter-lab", "--ip=0.0.0.0", "--no-browser", "--allow-root"]
