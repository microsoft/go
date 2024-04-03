## Pipelines

This directory contains Azure DevOps (AzDO) YAML pipelines for CI.

Pipeline definitions currently using each YAML file are:

### dnceng-public

* [`pr-pipeline.yml`](pr-pipeline.yml) - Required PR check.
  * [microsoft-go](https://dev.azure.com/dnceng/public/_build?definitionId=1099)
* [`pr-outerloop-pipeline.yml`](pr-outerloop-pipeline.yml) - Optional PR check. Runs outerloop.
  * [microsoft-go-outerloop](https://dev.azure.com/dnceng/public/_build/index?definitionId=1100)
    * Comment `/azp run microsoft-go-outerloop` on a PR to run.

### dnceng (internal)

* [`rolling-innerloop-pipeline.yml`](rolling-innerloop-pipeline.yml) - Triggers on merge, runs innerloop.
  * [microsoft-go-innerloop](https://dev.azure.com/dnceng/internal/_build?definitionId=1342)
* [`rolling-pipeline.yml`](rolling-pipeline.yml) - Triggers on merge, runs outerloop.
  * [microsoft-go-rolling](https://dev.azure.com/dnceng/internal/_build?definitionId=987)
* [`rolling-internal-pipeline.yml`](rolling-internal-pipeline.yml) - Triggers on merge. Builds, signs, and publishes. Does not run tests.
  * [microsoft-go](https://dev.azure.com/dnceng/internal/_build?definitionId=958)

The pipeline filenames are (mostly) based on the trigger scenario, not what they
do. This means we can change their content later without worrying about
filenames going out of date. (If we change a pipeline file's name, we also need
to update the web-UI-based AzDO pipeline to point at the new file. Each web UI
pipeline can only point at one YAML file, so this breaks old branches that
haven't renamed the file. It would be nice to avoid this.)

For more information about the style of these pipeline and template YAML files
and the quirks involved with the way they're implemented, visit
[pipeline-yml-style.md in microsoft/go-infra](https://github.com/microsoft/go-infra/blob/main/docs/pipeline-yml-style.md).

## Templates

The subdirectories hold AzDO pipeline YAML templates, based on type of template.

Quick link: [`jobs/go-builder-matrix-jobs.yml`](jobs/go-builder-matrix-jobs.yml)
defines the set of builders that should run based on the scenario.
