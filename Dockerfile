FROM angr/angr

USER angr

#setup virtenv so we can install things
ENV ORIG_PATH="${PATH}"
ENV PATH="/home/angr/.virtualenvs/angr/bin:${PATH}"

#fixup some of the out-of-date angr files
WORKDIR /home/angr/angr-dev
# RUN cd angr && git fetch && git checkout origin/master -- \
# angr/exploration_techniques/tracer.py \
# angr/sim_options.py

#Install the tracer package
RUN git clone https://github.com/angr/tracer.git tracer
WORKDIR /home/angr/angr-dev/tracer
RUN python ./setup.py install
RUN chmod +x /home/angr/.virtualenvs/angr/lib/python3.6/site-packages/shellphish_qemu-0.9.10-py3.6-linux-x86_64.egg/shellphish_qemu/bin/*
#Used these lines to help debug tracer.QEMURunner by adding debug statements to source
# RUN rm /home/angr/.virtualenvs/angr/lib/python3.6/site-packages/tracer-0.1-py3.6.egg
# RUN cp -r tracer /home/angr/.virtualenvs/angr/lib/python3.6/site-packages/

WORKDIR /job
COPY . .

# ENTRYPOINT python executor.py
ENV PATH="${ORIG_PATH}"
ENTRYPOINT bash