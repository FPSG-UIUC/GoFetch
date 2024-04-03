#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/sysfs.h>

#include <asm/cpu.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stephan van Schaik");
MODULE_DESCRIPTION("Apple M1 performance counter access");
MODULE_VERSION("0.0.1");

int
region_init(void);
void
region_exit(void);

int
sysregs_init(void);
void
sysregs_exit(void);

int
uncore_pmu_init(void);
void
uncore_pmu_exit(void);

static int __init
kmod_init(void)
{
	int rc;

	rc = region_init();

	if (rc) {
		return rc;
	}

	rc = sysregs_init();

	if (rc) {
		goto err_region_exit;
	}

	rc = uncore_pmu_init();

	if (rc) {
		goto err_sysregs_exit;
	}

	pr_info("kmod: initialized\n");

	return 0;

err_sysregs_exit:
	sysregs_exit();
err_region_exit:
	region_exit();
	return rc;
}

static void __exit
kmod_exit(void)
{
	printk(KERN_INFO "kmod: cleaning up\n");

	uncore_pmu_exit();
	sysregs_exit();
	region_exit();
}

module_init(kmod_init);
module_exit(kmod_exit);
