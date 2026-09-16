class Envrcctl < Formula
  include Language::Python::Virtualenv

  desc "Manage .envrc with managed blocks and OS-backed secrets"
  homepage "https://github.com/rioriost/envrcctl"
  url "https://github.com/rioriost/envrcctl/releases/download/0.4.0/envrcctl-0.4.0.tar.gz"
  sha256 "2a8a58fc427661bdbede8b8c4e211b859e4095b496c69b938aa63bb4eb5023e7"
  license "MIT"

  depends_on "python@3.14"

  on_macos do
    on_arm do
      depends_on macos: :tahoe

      resource "envrcctl-macos-auth-arm64" do
        url "https://github.com/rioriost/envrcctl/releases/download/0.4.0/envrcctl-macos-auth-0.4.0-arm64.tar.gz"
        sha256 "e93bd4b4227e86e92d519b5e13b7e226b68db9ea329f800b5fad8d01ee518861"
      end
    end
  end

  resource "click" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/click/8.4.2/click-8.4.2-py3-none-any.whl", using: :nounzip
    sha256 "e6f9f66136c816745b9d65817da91d61d957fb16e02e4dcd0552553c5a197b76"
  end

  resource "typer" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/typer/0.26.8/typer-0.26.8-py3-none-any.whl", using: :nounzip
    sha256 "3512ca79ac5c11113414b36e80281b872884477722440691c89d1112e321a49c"
  end

  resource "annotated-doc" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/annotated-doc/0.0.4/annotated_doc-0.0.4-py3-none-any.whl", using: :nounzip
    sha256 "571ac1dc6991c450b25a9c2d84a3705e2ae7a53467b5d111c24fa8baabbed320"
  end

  resource "rich" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/rich/15/rich-15.0.0-py3-none-any.whl", using: :nounzip
    sha256 "33bd4ef74232fb73fe9279a257718407f169c09b78a87ad3d296f548e27de0bb"
  end

  resource "shellingham" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/shellingham/1.5.4/shellingham-1.5.4-py2.py3-none-any.whl", using: :nounzip
    sha256 "7ecfff8f2fd72616f7481040475a65b2bf8af90a56c89140852d1120324e8686"
  end

  resource "markdown-it-py" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/markdown-it-py/4.2/markdown_it_py-4.2.0-py3-none-any.whl", using: :nounzip
    sha256 "9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a"
  end

  resource "pygments" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/pygments/2.20/pygments-2.20.0-py3-none-any.whl", using: :nounzip
    sha256 "81a9e26dd42fd28a23a2d169d86d7ac03b46e2f8b59ed4698fb4785f946d0176"
  end

  resource "mdurl" do
    url "https://ms-feed-25.pkgs.visualstudio.com/6f084628-a36d-42cb-934d-057357e379dc/_packaging/49d7402f-07bb-4b18-a9ce-086e6e98a554/pypi/download/mdurl/0.1.2/mdurl-0.1.2-py3-none-any.whl", using: :nounzip
    sha256 "84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8"
  end

  resource "envrcctl-wheel" do
    url "https://github.com/rioriost/envrcctl/releases/download/0.4.0/envrcctl-0.4.0-py3-none-any.whl", using: :nounzip
    sha256 "6553b46696c5d6bf83b0515534271700b28890a52931e2dbab0c51642af48dfb"
  end

  def install
    # All Python packages are checksummed wheels fetched by Homebrew in advance.
    ENV["PIP_NO_INDEX"] = "1"
    ENV["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    venv = virtualenv_create(libexec, "python3.14")
    venv.pip_install resource("click"), build_isolation: false
    venv.pip_install resource("typer"), build_isolation: false
    venv.pip_install resource("annotated-doc"), build_isolation: false
    venv.pip_install resource("rich"), build_isolation: false
    venv.pip_install resource("shellingham"), build_isolation: false
    venv.pip_install resource("markdown-it-py"), build_isolation: false
    venv.pip_install resource("pygments"), build_isolation: false
    venv.pip_install resource("mdurl"), build_isolation: false
    venv.pip_install resource("envrcctl-wheel"), build_isolation: false

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
    assert_path_exists bin/"envrcctl"
    assert_match "Manage .envrc", shell_output("#{bin}/envrcctl --help")
    if OS.mac? && Hardware::CPU.arm?
      assert_path_exists bin/"envrcctl-macos-auth"
      assert_match "Usage:", shell_output("#{bin}/envrcctl-macos-auth --help")
    end
  end
end
