## Pipelines

This directory contains Azure DevOps (AzDO) YAML pipelines for CI.

* [The dnceng-public Go folder](https://dev.azure.com/dnceng-public/public/_build?definitionScope=%5CMicrosoft%5Cgo) contains public Go pipelines used by PR validation.
* [The internal dnceng Go folder](https://dev.azure.com/dnceng/internal/_build?definitionScope=%5CMicrosoft%5Cgo) contains internal builds, like CI.

Each pipeline yml file contains links to its pipeline or pipelines.

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

Quick link: [`stages/go-builder-matrix-stages.yml`](stages/go-builder-matrix-stages.yml)
defines the set of builders that should run based on the scenario.
