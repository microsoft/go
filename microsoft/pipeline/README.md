## Pipelines

This directory contains Azure DevOps (AzDO) YAML pipelines for CI.

The pipeline filenames are (mostly) based on the trigger scenario, not what they
do. This means we can change their content later without worrying about
filenames going out of date. (If we change a pipeline file's name, we also need
to update the web-UI-based AzDO pipeline to point at the new file. Each web UI
pipeline can only point at one YAML file, so this breaks old branches that
haven't renamed the file. It would be nice to avoid this.)

Each pipeline yml file contains a comment describing what it does.

## Templates

The subdirectories hold AzDO pipeline YAML templates, based on type of template.

Quick link: [`jobs/go-builder-matrix-jobs.yml`](jobs/go-builder-matrix-jobs.yml)
defines the set of builders that should run based on the scenario.
