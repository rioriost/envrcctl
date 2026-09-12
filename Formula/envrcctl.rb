class Envrcctl < Formula
  include Language::Python::Virtualenv

  desc "Manage .envrc with managed blocks and OS-backed secrets"
  homepage "https://github.com/rioriost/envrcctl"
  url "https://github.com/rioriost/envrcctl/releases/download/0.3.1/envrcctl-0.3.1.tar.gz"
  sha256 "abc91553fd389131e56d53f0e5df0d189b5404cf9a16cd07a2aa51e503a0cec5"
  license "MIT"

  depends_on "python@3.14"

  resource "click" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/click/8.4.2/click-8.4.2.tar.gz"
    sha256 "9a6cea6e60b17ebe0a44c5cc636d94f09bd66142c1cd7d8b4cd731c4917a15f6"
  end

  resource "typer" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/typer/0.26.8/typer-0.26.8.tar.gz"
    sha256 "c244a6bd558886fe3f8780efb6bdd28bb9aff005a94eedebaa5cb32926fe2f7e"
  end

  resource "annotated-doc" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/annotated-doc/0.0.4/annotated_doc-0.0.4.tar.gz"
    sha256 "fbcda96e87e9c92ad167c2e53839e57503ecfda18804ea28102353485033faa4"
  end

  resource "rich" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/rich/15/rich-15.0.0.tar.gz"
    sha256 "edd07a4824c6b40189fb7ac9bc4c52536e9780fbbfbddf6f1e2502c31b068c36"
  end

  resource "shellingham" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/shellingham/1.5.4/shellingham-1.5.4.tar.gz"
    sha256 "8dbca0739d487e5bd35ab3ca4b36e11c4078f3a234bfce294b0a0291363404de"
  end

  resource "markdown-it-py" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/markdown-it-py/4.2/markdown_it_py-4.2.0.tar.gz"
    sha256 "04a21681d6fbb623de53f6f364d352309d4094dd4194040a10fd51833e418d49"
  end

  resource "pygments" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/pygments/2.20/pygments-2.20.0.tar.gz"
    sha256 "6757cd03768053ff99f3039c1a36d6c0aa0b263438fcab17520b30a303a82b5f"
  end

  resource "mdurl" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/mdurl/0.1.2/mdurl-0.1.2.tar.gz"
    sha256 "bb413d29f5eea38f31dd4754dd7377d4465116fb207585f97bf925588687c1ba"
  end

  on_macos do
    on_arm do
      resource "envrcctl-macos-auth-arm64" do
        url "https://github.com/rioriost/envrcctl/releases/download/0.3.1/envrcctl-macos-auth-0.3.1-arm64.tar.gz"
        sha256 "010ffe06d9859d74769c0938e4790f40efeb10d59c805bedc6f3aad65521d574"
      end
    end
  end

  def install
    venv = virtualenv_create(libexec, "python3.14")
    venv.pip_install resource("click")
    venv.pip_install resource("typer")
    venv.pip_install resource("annotated-doc")
    venv.pip_install resource("rich")
    venv.pip_install resource("shellingham")
    venv.pip_install resource("markdown-it-py")
    venv.pip_install resource("pygments")
    venv.pip_install resource("mdurl")
    venv.pip_install buildpath

    bin.install_symlink libexec/"bin/envrcctl"

    if OS.mac? && Hardware::CPU.arm?
      resource("envrcctl-macos-auth-arm64").stage do
        bin.install "envrcctl-macos-auth"
      end
    end

    bash_completion.install "completions/envrcctl.bash" => "envrcctl"
    zsh_completion.install "completions/envrcctl.zsh" => "_envrcctl"
    fish_completion.install "completions/envrcctl.fish"
  end

  test do
    assert_predicate bin/"envrcctl", :exist?
    assert_match "Manage .envrc", shell_output("#{bin}/envrcctl --help")
    if OS.mac? && Hardware::CPU.arm?
      assert_predicate bin/"envrcctl-macos-auth", :exist?
    end
  end
end
