FROM shieldai_simulateur_attaque_img:latest

RUN apt-get -o APT::Get::AllowUnauthenticated=true update -qq && \
    apt-get -o APT::Get::AllowUnauthenticated=true \
            install -y -qq --no-install-recommends openssh-server && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /root/.ssh && chmod 700 /root/.ssh

CMD ["sleep", "infinity"]
