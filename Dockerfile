FROM angr/angr

USER angr

#setup virtenv so we can install things
ENV ORIG_PATH="${PATH}"
ENV PATH="/home/angr/.virtualenvs/angr/bin:${PATH}"

WORKDIR /job
COPY --chown=angr:angr . .
RUN cd target && tar xvf target.tar.gz

ENTRYPOINT ["python","executor.py"]
#ENV PATH="${ORIG_PATH}"
#ENTRYPOINT bash
