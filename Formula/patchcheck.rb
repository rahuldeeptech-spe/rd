class Patchcheck < Formula
  desc "Read-only checker for PHP2Shell, Node2Shell and other live runtime vulnerabilities"
  homepage "https://github.com/rahuldeeptech-spe/rd"
  url "https://github.com/rahuldeeptech-spe/rd/releases/download/v1.4.0/patchcheck-v1.4.0.tar.gz"
  sha256 "cc2921292da1c0720b1ad48c66c7cdf0fb308f9f8cad75100457fb7df3ae4e30"
  license "MIT"

  def install
    libexec.install "patchcheck.sh", "advisories.tsv"
    (bin/"patchcheck").write <<~EOS
      #!/bin/bash
      exec /bin/bash "#{libexec}/patchcheck.sh" "$@"
    EOS
    doc.install "README.md", "CHANGELOG.md"
  end

  test do
    assert_match "patchcheck #{version}", shell_output("#{bin}/patchcheck --version")
  end
end
