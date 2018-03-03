FROM python:3
MAINTAINER Shane Frasier <jeremy.frasier@beta.dhs.gov>

#ENV MY_UID=421 \
#    INSTALL_IPYTHON="Yes Please" \
ENV MY_SRC="/usr/src/boat" \
    MY_HOME="/home/boat"

#RUN groupadd --system -g ${MY_UID} boat && \
#    useradd -m --system -u ${MY_UID} --gid boat boat

COPY . ${MY_SRC}

RUN if [ -n "${INSTALL_IPYTHON}" ]; then pip install ipython; fi && \
    pip install --no-cache-dir -e ${MY_SRC}

# USER boat
WORKDIR ${MY_HOME}

ENTRYPOINT ["dmarc-s3-import"]
