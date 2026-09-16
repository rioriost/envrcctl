#compdef envrcctl

_envrcctl_completion() {
  eval $(env _TYPER_COMPLETE_ARGS="${words[1,$CURRENT]}" _ENVRCCTL_COMPLETE=complete_zsh envrcctl)
}

compdef _envrcctl_completion envrcctl
