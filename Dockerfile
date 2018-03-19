FROM python:3
MAINTAINER Shane Frasier <jeremy.frasier@beta.dhs.gov>

# Update pip and setuptools to the latest versions
RUN pip install --no-cache-dir --upgrade pip setuptools

ENV MY_SRC="/usr/src/boat" \
    MY_HOME="/home/boat"

#RUN groupadd --system -g ${MY_UID} boat && \
#    useradd -m --system -u ${MY_UID} --gid boat boat

# RUN pip install --no-cache-dir --upgrade https://github.com/jsf9k/dmarc-import.git
COPY . ${MY_SRC}
RUN pip install --no-cache-dir ${MY_SRC}

# USER boat
WORKDIR ${MY_HOME}

ENTRYPOINT ["dmarc-s3-import"]
