FROM itsafeaturemythic/mythic_python_base:latest

# Mythic v4 container library (official upgrade path from the 3.4 -> 4.0 docs).
RUN pip3 install mythic_container==0.7.0rc9 cryptography
RUN pip3 install --upgrade --force-reinstall grpcio>=1.78.0

WORKDIR /Mythic/
CMD ["python3", "main.py"]
