# Microsoft build of Go pipelines

This directory contains Azure DevOps (AzDO) YAML pipelines for CI.

* [The dnceng-public Go folder](https://dev.azure.com/dnceng-public/public/_build?definitionScope=%5CMicrosoft%5Cgo) contains public Go pipelines used by PR validation.
* [The internal dnceng Go folder](https://dev.azure.com/dnceng/internal/_build?definitionScope=%5CMicrosoft%5Cgo) contains internal builds, like CI.

Each pipeline yml file contains links to its pipeline or pipelines.

Some pipelines are generated from `*.gen.yml` files by [pipelineymlgen](https://github.com/microsoft/go-infra/blob/main/cmd/pipelineymlgen/README.md).
They contain a "DO NOT EDIT" warning at the top of the file and the automated tests ensure reproducibility.
Use `pwsh eng/run.ps1 pipelineymlgen` to regenerate them locally.

For more information about the style of these pipeline and template YAML files
and the quirks involved with the way they're implemented, visit
[pipeline-yml-style.md in microsoft/go-infra](https://github.com/microsoft/go-infra/blob/main/docs/pipeline-yml-style.md).

### Naming convention

Pipeline filenames aren't very flexible, for a few reasons:

* Some AzDO pipeline configuration is costly to set up and invalidated by pipeline renames, in particular signing authorization.
  * The pipeline's name in AzDO is not necessarily tied to the filename, but for clarity they are generally aligned.
* If we change a pipeline file's name, we also need to update the web-UI-based AzDO pipeline to point at the new file. Each web UI pipeline can only point at one YAML file, so this breaks old branches that haven't renamed the file. We can do a synchronized backport, but that can be disruptive.

For this reason, it generally makes sense to create a pipeline filename that focuses on the trigger scenario, not what the pipeline does or how.
This means we have more flexibility later to change it without worrying about the filename becoming misleading or stale.

## Templates

The subdirectories hold AzDO pipeline YAML templates, based on type of template.

Quick link: [`stages/go-builder-matrix-stages.yml`](stages/go-builder-matrix-stages.yml)
defines the set of builders that should run based on the scenario.
