## Pipelines

This directory contains Azure DevOps (AzDO) YAML pipelines for CI.

Pipeline definitions currently using each YAML file are:

* [`pr-pipeline.yml`](pr-pipeline.yml) - Required PR check.
  * [microsoft-go-private-github](https://dev.azure.com/dnceng/internal/_build?definitionId=969)
* [`pr-outerloop-pipeline.yml`](pr-outerloop-pipeline.yml) - Optional PR check.
  Runs outerloop.
  * [microsoft-go-pr-outerloop](https://dev.azure.com/dnceng/internal/_build?definitionId=989)
    * Comment `/azp run microsoft-go-pr-outerloop` on a PR to run.
* [`rolling-pipeline.yml`](rolling-pipeline.yml) - Triggers on merge, runs
  innerloop + outerloop.
  * [microsoft-go-rolling](https://dev.azure.com/dnceng/internal/_build?definitionId=987)
* [`rolling-internal-pipeline.yml`](rolling-internal-pipeline.yml) - Triggers on
  merge. Builds, signs, and publishes. Runs innerloop, and won't publish if
  innerloop fails.
  * [microsoft-go](https://dev.azure.com/dnceng/internal/_build?definitionId=958)

The pipeline filenames are (mostly) based on the trigger scenario, not what they
do. This means we can change their content later without worrying about
filenames going out of date. (If we change a pipeline file's name, we also need
to update the web-UI-based AzDO pipeline to point at the new file. Each web UI
pipeline can only point at one YAML file, so this breaks old branches that
haven't renamed the file. It would be nice to avoid this.)

## Templates

The subdirectories hold AzDO pipeline YAML templates, based on type of template.

Quick link: [`jobs/go-builder-matrix-jobs.yml`](jobs/go-builder-matrix-jobs.yml)
defines the set of builders that should run based on the scenario.
