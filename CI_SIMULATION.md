## Using act cli to test github actions

Install `act`:

```shell
brew install act
```

Create an event file:

```shell
cat <<EOF > ci_push_tag_test.json
{
  "ref": "refs/tags/v0.0.1",
  "repository": {
    "full_name": "kdex-tech/host-manager"
  },
  "event_name": "push" 
}
EOF
```

Run the workflow:

```shell
## Just run the base CI
act .github/workflows/ci.yml

export GITHUB_TOKEN=ghp_...

act -e ci_push_tag_test.json -s "GITHUB_TOKEN=${GITHUB_TOKEN}" --workflows .github/workflows/ci.yml
```