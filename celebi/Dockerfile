FROM itsafeaturemythic/mythic_python_base:latest

# Mythic v4 container library (official upgrade path from the 3.4 -> 4.0 docs).
RUN pip3 install mythic_container==0.7.0rc9
RUN pip3 install --upgrade --force-reinstall grpcio>=1.78.0

RUN apt update
RUN apt install -y gcc-mingw-w64-i686
RUN apt install -y gcc-mingw-w64-x86-64
RUN apt install -y default-jre
RUN apt install -y zip

RUN mkdir /crystal-palace/
ADD https://tradecraftgarden.org/download/cpdist-latest.tgz /crystal-palace.tgz
RUN tar -xvzf /crystal-palace.tgz -C /crystal-palace/

WORKDIR /Mythic/
CMD ["python3", "main.py"]
