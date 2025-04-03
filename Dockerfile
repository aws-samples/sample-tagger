
FROM public.ecr.aws/amazonlinux/amazonlinux:2023
RUN dnf update -y &&     dnf install -y nginx procps shadow-utils &&     dnf clean all

RUN rm -rf /usr/share/nginx/html/*
COPY ./build/ /usr/share/nginx/html/
EXPOSE 80
ENTRYPOINT ["nginx", "-g", "daemon off;"]
