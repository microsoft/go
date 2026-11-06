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

## Testing an upstream Go change

Manually run a PR or rolling pipeline using **Run pipeline** in Azure DevOps.
Select the outer repository branch (or ref under **Branch/tag**) to test, then set
`submoduleRef` to an upstream commit SHA or Gerrit ref, such as
`refs/changes/34/123434/2`. Leave it as `nil` to use the pinned submodule commit.
The override applies to both innerloop and outerloop pipelines.

Overrides are fetched anonymously from `https://go.googlesource.com/go`.
Public PR pipelines also accept `submoduleRepository`, for example an HTTPS GitHub
fork URL, to test a commit that has not been uploaded to Gerrit. This parameter is
only used when `submoduleRef` is set; internal rolling pipelines always fetch
overrides from the public Go repository, without the internal mirror credentials.

The pipeline stages the selected submodule revision locally before applying the
usual Microsoft patches. Patches are still applied, and patch conflicts fail the
build as usual. No branch or commit needs to be created or pushed for this override.
