FROM python:3
MAINTAINER Mark Feldhousen <mark.feldhousen@hq.dhs.gov>

ARG MY_UID=421
ARG INSTALL_IPYTHON="Yes Please"
ARG MY_SRC="/usr/src/boat"
ENV MY_HOME="/home/boat"

RUN groupadd --system -g ${MY_UID} boat && useradd -m --system -u ${MY_UID} --gid boat boat

RUN if [ -n "${INSTALL_IPYTHON}" ]; then pip install ipython; fi

WORKDIR ${MY_SRC}

COPY . ${MY_SRC}
RUN pip install --no-cache-dir -e .

USER boat
WORKDIR ${MY_HOME}
RUN mkdir .aws
RUN ln -snf /run/secrets/aws_config .aws/config
RUN ln -snf /run/secrets/aws_credentials .aws/credentials

ENTRYPOINT ["dmarc-s3-import"]
